package Robin;

import org.xbill.DNS.*;

import java.io.IOException;
import java.util.*;

public class dnssecresolver {

    /*
        ReferenceToItself Exception
        This exception gets thrown when a loop is detected while query resolution, i.e,
        when the name server provides a self-reference during resolution.
        Example URL: rhybar.cz.
     */
    class ReferenceToItself extends Exception
    {
        public ReferenceToItself() {}

        public ReferenceToItself(String message)
        {
            super(message);
        }
    }

     /*
        DNSSecNotSupportedException Exception
        This exception gets thrown when resolver determines that
        the DNSSec is not enabled, i.e., does not support DNSSec protocol for resolution
     */
    class DNSSecNotSupportedException extends Exception
    {
        public DNSSecNotSupportedException() {}

        public DNSSecNotSupportedException(String message)
        {
            super(message);
        }
    }

    /*
        DNSSecVaidationError exception
        This exception gets thrown when resolver determines that
        either the RRSig and the response do not match or there was error is authenticating the DS of server.
     */
    class DNSSecVaidationError extends Exception
    {
        public DNSSecVaidationError() {}

        public DNSSecVaidationError(String message)
        {
            super(message);
        }
    }

    class NSECRecordFound extends Exception
    {
        public NSECRecordFound() {}

        public NSECRecordFound(String message)
        {
            super(message);
        }
    }

    List<String> RootServersList;   // list of all the root servers
    List<DSRecord> DSAnchorsList;   // list of parent DS
    long querytime;                 // to keep track of implementation vs network time
    Name keyQuery;

    /* Initializes with IP address of 13 root servers
    Data courtesy: https://www.iana.org/domains/root/servers */
    public void initializeRootServers(){
        RootServersList = new ArrayList<String>();
        RootServersList.add("198.41.0.4");
        RootServersList.add("199.9.14.201");
        RootServersList.add("192.33.4.12");
        RootServersList.add("199.7.91.13");
        RootServersList.add("192.203.230.10");
        RootServersList.add("192.5.5.241");
        RootServersList.add("192.112.36.4");
        RootServersList.add("198.97.190.53");
        RootServersList.add("192.36.148.17");
        RootServersList.add("192.58.128.30");
        RootServersList.add("193.0.14.129");
        RootServersList.add("199.7.83.42");
        RootServersList.add("202.12.27.33");
    }

    /* Initializing a trust anchor to verify the root server*/
    public void initializeDSRecords(){
        DSAnchorsList = new ArrayList<DSRecord>();
        String rec  = "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";
        String rec2 = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
        try {
            DSRecord record = new DSRecord(Name.fromString("."),DClass.IN,172800,19036,
                    DNSSEC.Algorithm.RSASHA256,DSRecord.SHA256_DIGEST_ID,rec.getBytes());

            DSRecord record2 = new DSRecord(Name.fromString("."),DClass.IN,172800,20326,
                    DNSSEC.Algorithm.RSASHA256,DSRecord.SHA256_DIGEST_ID,rec2.getBytes());

            //DSAnchorsList.add(record);
            //DSAnchorsList.add(record2);
            keyQuery = Name.fromString(".");
        } catch (TextParseException e) {
            e.printStackTrace();
        }
    }

    /* Constructor */
    public dnssecresolver(){
        initializeRootServers();
        initializeDSRecords();
        querytime = 0;

    }

    /*
    * Function: dnssecMessageGenerator().
    * Return type: Message
    * This function is used for sending a dnsSec query to the host server.
    * it creates an object of SimpleResolver to send a request and returns the "Message" response received.
    * */
    public Message dnssecMessageGenerator(String hname, String inputString, int type) throws Exception{
        long start = System.currentTimeMillis();
        SimpleResolver resolver = new SimpleResolver(hname);
        resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
        resolver.setIgnoreTruncation(false);
        Record rec = Record.newRecord(Name.fromString(inputString,Name.root),type,DClass.IN);
        Message msg = Message.newQuery(rec);
        Message recv = resolver.send(msg);
        querytime += (System.currentTimeMillis() - start);
        return recv;
    }

    /*
        Function: validateMessage
        Return Type: void
        This function performs 4 key validations:
        1. Requesting the DNSKey from the host server.
        2. Validating the child zone with the DS received from parent zone. (Step 2 below)
        3. Validating the received response RRSig using the Key signing keys (Step 1 - 3)
        4. Validating the actual DNS received message from server with the Zone signing key received in DNSKey message. (Step 4-5)
     */
    public void validateMessage(Message msg, String hostname, int section) throws org.xbill.DNS.DNSSEC.DNSSECException,
            IOException, DNSSecNotSupportedException, DNSSecVaidationError, NSECRecordFound, java.net.SocketTimeoutException{
        RRSIGRecord recvRecSign;
        List<DNSKEYRecord> ZSKList  = new ArrayList<DNSKEYRecord>();
        List<DNSKEYRecord> KSKList  = new ArrayList<DNSKEYRecord>();
        List<RRSIGRecord> RRSigList = new ArrayList<RRSIGRecord>();

        Message keymsg = null;

        try {
            keymsg = dnssecMessageGenerator(hostname, keyQuery.toString(), Type.DNSKEY);
        } catch (Exception e) {
            throw new java.net.SocketTimeoutException();
        }


        if(keymsg == null){
            throw new DNSSecNotSupportedException();
        }

        // Step 1: parse whole DNSKey to get zsk, ksk and rrsig list
        RRset[] keyrrset = keymsg.getSectionRRsets(Section.ANSWER);
        for(RRset rriter : keyrrset){
            Iterator keyiter = rriter.rrs();
            while (keyiter.hasNext()){
                Record rec = (Record) keyiter.next();
                if(rec.getType() == Type.DNSKEY){
                    DNSKEYRecord record = (DNSKEYRecord) rec;
                    if (record.getFlags() == 256)
                        ZSKList.add(record);
                    else if (record.getFlags() == 257)
                        KSKList.add(record);
                }
            }

            keyiter = rriter.sigs();
            while(keyiter.hasNext()){
                Record record = (Record) keyiter.next();
                if(record.getType() == Type.RRSIG){
                    RRSigList.add((RRSIGRecord)record);
                }
            }
        }

        // Step 2: If received ksk records, validate the server with old DS anchors
        if(KSKList.size() == 0 || RRSigList.size() == 0){
            throw new DNSSecNotSupportedException();
        }

        boolean DSValidatated = false;
        for(DNSKEYRecord KSKkey: KSKList){
            DSRecord keyDS = new DSRecord(KSKkey.getName(),KSKkey.getDClass(),KSKkey.getTTL(),2,KSKkey);
            for(DSRecord anchor: DSAnchorsList) {
                if(anchor.getFootprint() == keyDS.getFootprint()){
                    if(anchor.hashCode() == keyDS.hashCode()) {
                        DSValidatated = true;
                    }
                }
            }
        }

        if(!DSValidatated && !keyQuery.toString().equals(".")){ // anchor cannot be validated
            throw new DNSSecVaidationError();
        }

        // Step 3: validate the DNSKey message rrsig using the received ksk
        for(DNSKEYRecord KSKkey: KSKList){
            for(RRSIGRecord keyrrsig : RRSigList)
            {
                if(KSKkey.getFootprint() == keyrrsig.getFootprint())
                {
                    DNSSEC.verify(keyrrset[0],keyrrsig,KSKkey);
                }
            }
        }

        // reuse, recycle, save earth
        DSAnchorsList.clear();
        RRSigList.clear();

        // Step 4: repopulate ds and rrsig lists from received message to validate actual message.
        RRset[] recvMsgRRset = msg.getSectionRRsets(section);
        for(RRset rriter : recvMsgRRset){
            Iterator msgiter = rriter.rrs();
            while (msgiter.hasNext()){
                Record record = (Record) msgiter.next();
                if(record.getType() == Type.DS){
                    DSAnchorsList.add((DSRecord) record);
                }
//                else if(record.getType() == Type.NSEC || record.getType() == Type.NSEC3){
//                    throw  new NSECRecordFound();
//                }
                else if(record.getType() == Type.RRSIG){
                    RRSigList.add((RRSIGRecord)record);
                    keyQuery = record.getName();
                }
            }

            msgiter = rriter.sigs();
            while(msgiter.hasNext()){
                Record record = (Record) msgiter.next();
                if(record.getType() == Type.RRSIG){
                    RRSigList.add((RRSIGRecord)record);
                    keyQuery = record.getName();
                }
                if(record.getType() == Type.DS){
                    DSAnchorsList.add((DSRecord) record);
                }
            }
        }

        // Step 5: validate the message
        boolean validateMsg = false;
        for(RRset msgRR : recvMsgRRset){
            Iterator msgiter = msgRR.sigs();
            while(msgiter.hasNext()){
                RRSIGRecord sigrecord = (RRSIGRecord)msgiter.next();
                // check with zsk
                for(DNSKEYRecord zsk : ZSKList){
                    if(sigrecord.getFootprint() == zsk.getFootprint()){
                        DNSSEC.verify(msgRR,sigrecord,zsk);
                        validateMsg = true;
                    }
                }
            }
        }

        if(!validateMsg) throw new DNSSecNotSupportedException();
    }

    /*
        Function: dnssecQueryResolver
        Return type: Message
        This is the core function that takes in query and type and resolves the query one zone at a time.
        It checks if we have received the answer to query posted to the domain server. If yes, it returns the result
        to the controller, else it further resolves the received result (in case CNAME/ NS records that require further resolving).
     */
    public Message dnssecQueryResolver(String query, int type) throws org.xbill.DNS.DNSSEC.DNSSECException,
            IOException, DNSSecNotSupportedException, DNSSecVaidationError, NSECRecordFound, ReferenceToItself{
        String inputString = query;
        Message ret = null;

        if(inputString.contains("www")){
            inputString = query.split("www.")[1];
        }
        else if(inputString.contains("http")){
            //inputString = query.substring(8,query.length());
            inputString = query.split("//")[1];
        }

        if(!inputString.endsWith(".")){
            inputString+=".";
        }

        // at this point we have site name and domain only
        List<String> nameServerList = new LinkedList<String>();
        for(String roots : RootServersList)
        { // for each rootserver
            boolean keepTryingRoot = false;
            nameServerList.add(roots);
            while(nameServerList.size() > 0)
            {
                String hostName = nameServerList.get(0);
                //MessageBox("Host: "+hostName+" , input: "+inputString);
                Message recv = null;
                try {
                    recv = dnssecMessageGenerator(hostName,inputString, type);
                } catch (java.net.SocketTimeoutException e) {
                    keepTryingRoot = true;
                    nameServerList.remove(0);
                    break;
                }
                catch (Exception e){

                }

                // check if received message is valid
                if(recv.getHeader().getRcode() == Rcode.NOERROR)
                {
                    //System.out.println(recv);

                    // now parse all records to get new hostname
                    Record[] answerRec = recv.getSectionArray(Section.ANSWER);

                    if(answerRec.length > 0)
                    {
                        int index = 0;
                        try {
                            validateMessage(recv,hostName,Section.ANSWER);
                        } catch (DNSSEC.DNSSECException | NSECRecordFound | DNSSecNotSupportedException | DNSSecVaidationError e) {
                           throw e;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        while(index < answerRec.length-1 && (answerRec[index].getType() == Type.RRSIG )){
                            ++index;
                        }

                        switch(answerRec[index].getType()){
                            case Type.A:
                            case Type.NS:
                            case Type.MX:
                            {
                                //MessageBox("Got Answer for query: "+inputString+" ,answer: "+answerRec[0].rdataToString());
                                return recv;
                            }
                            case Type.CNAME:
                            {
                                //MessageBox("Got CNAME for query: "+inputString+" ,answer: "+answerRec[0].rdataToString());
                                nameServerList.clear();
                                keyQuery = Name.fromString(".");
                                DSAnchorsList.clear();
                                Message cnameRecv = dnssecQueryResolver(answerRec[index].rdataToString(),type);
                                return cnameRecv;
                            }
                            default:
                            {

                            }
                        }

                    }
                    else if(recv.getSectionArray(Section.ADDITIONAL).length > 1)
                    {

                        try {
                            validateMessage(recv,hostName,Section.AUTHORITY);
                        } catch (DNSSEC.DNSSECException | NSECRecordFound | DNSSecNotSupportedException | DNSSecVaidationError e) {
                            throw e;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        // try from authority
                        Record[] additionalrecord = recv.getSectionArray(Section.ADDITIONAL);
                        // check for self reference (as in rhybar.cz. site)
                        for(Record addrecords : additionalrecord){
                            if(addrecords.getType() == Type.A && nameServerList.contains(addrecords.rdataToString())){
                                throw new ReferenceToItself();
                            }
                        }
                        nameServerList.clear();
                        for(Record addrecords : additionalrecord){
                            if(addrecords.getType() == Type.A){
                                nameServerList.add(addrecords.rdataToString());
                            }
                        }
                    }
                    else if(recv.getSectionArray(Section.AUTHORITY).length > 0)
                    {
                        try {
                            validateMessage(recv,hostName,Section.AUTHORITY);
                        } catch (DNSSEC.DNSSECException | NSECRecordFound | DNSSecNotSupportedException | DNSSecVaidationError e) {
                            throw e;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        Record question = recv.getQuestion();
                        Record[] authorityrecord = recv.getSectionArray(Section.AUTHORITY);
                        if(authorityrecord[0].getType() == Type.SOA && question.getType() == Type.MX){
                            return recv;
                        }
                        else if(authorityrecord[0].getType() == Type.NS && question.getType() == Type.NS){
                            return recv;
                        }
                        else if(authorityrecord[0].getType() == Type.MX && question.getType() == Type.MX){
                            return recv;
                        }
                        else if(authorityrecord[0].getType() == Type.NS){
                            // resolve the NS and return IP
                            String oldKeyQuery = keyQuery.toString();
                            nameServerList.clear();
                            keyQuery = Name.fromString(".");
                            DSAnchorsList.clear();
                            Message nsresp = dnssecQueryResolver(authorityrecord[0].rdataToString(),Type.A);
                            //MessageBox(nsresp.toString());
                            keyQuery = Name.fromString(oldKeyQuery); // restore the keyQuery
                            if(nsresp.getSectionArray(Section.ANSWER).length > 0)
                            {
                                Record[] respanswrec = nsresp.getSectionArray(Section.ANSWER);
                                for(Record respansw : respanswrec){
                                    if(respansw.getType() == Type.A)
                                        nameServerList.add(respansw.rdataToString());
                                }
                            }
                            else if(nsresp.getSectionArray(Section.ADDITIONAL).length > 1)
                            {
                                Record[] respaddrec = nsresp.getSectionArray(Section.ADDITIONAL);
                                for(Record respadd : respaddrec){
                                    if(respadd.getType() == Type.A)
                                        nameServerList.add(respadd.rdataToString());
                                }
                            }
                        }

                    }
                    else{ // some error, keep retry
                        keepTryingRoot = true;
                        break;
                    }
                }
                else { // retry with other root server
                    if(recv.getHeader().getRcode() != Rcode.NXDOMAIN){
                        MessageBox("Retry with other root server");
                        keepTryingRoot = true;
                    }
                    nameServerList.remove(0);
                    break;
                }
            }


            if(keepTryingRoot)
                continue;
            else
                break;
        }

        return ret;
    }

    /*
    * Function : dnssecController
    * Return type: long (return time taken by query)
    * This is a controller function for dns resolver that provides the statistics such as time taken by the query to run.
    * It is also responsible for finally printing the output of the mydig (similar to requested in assignment).
     */
    public long dnssecController(String query, int type) {
        long start= System.currentTimeMillis();
        Message ret = null;
        try {
            ret = dnssecQueryResolver(query, type);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DNSSecNotSupportedException e) {
            System.out.println("DNSSec not supported");
            return querytime;
        } catch (DNSSecVaidationError | DNSSEC.DNSSECException dnsSecVaidationError) {
            System.out.println("DNSSec verification failed");
            return querytime;
        } catch (NSECRecordFound e){
            System.out.println("DNSSEC not supported for query: "+query);
            return querytime;
        } catch (ReferenceToItself e){
            System.out.println("DNSSec verification failed");
            System.out.println("Nameserver gave reference to itself, lame. query: "+query);
            return querytime;
        }

        long total = System.currentTimeMillis() - start;
        if(ret == null)
        {
            MessageBox("Error: Could not resolve or no such query: "+query);
            return total;
        }
        MessageBox("QUESTION SECTION:");
        MessageBox(ret.getQuestion().toString());
        Record[] authrec = ret.getSectionArray(Section.AUTHORITY);
        Record[] ansrec = ret.getSectionArray(Section.ANSWER);
        MessageBox("ANSWER SECTION:");
        if(ansrec.length > 0){
            for(Record data : ansrec){
                MessageBox(data.toString());
            }
        }
        else if(authrec.length > 0){
            for(Record data : authrec){
                MessageBox(data.toString());
            }
        }

        MessageBox("Query time: "+total);
        Date now = new Date();
        MessageBox("WHEN: "+now);
        MessageBox("MSG SIZE rcvd: "+ret.numBytes());
        //System.out.println("Total Time: "+total+" , NW time: "+querytime+" ,java time: "+(total-querytime));
        return total;
    }

    public static void main(String args[]){
        if(args.length < 2){
            System.out.println("Invalid input size to dns-sec resolver: "+args.length);
            return;
        }
        String input = args[0];
        int type = Type.A;
        long time = 0;
        switch (args[1]){
            case "A":
                type = Type.A;
                break;
            case "NS":
                type = Type.NS;
                break;
            case "MX":
                type = Type.MX;
                break;
        }

        dnssecresolver resolver = new dnssecresolver();
        try {
            //resolver.dnssecController("http://dnssec-failed.org",1);
            //resolver.dnssecController("eurid.eu",1);
            resolver.dnssecController(args[0],type);
            //resolver.dnssecController("",1);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }

    public void MessageBox(String ip){

        System.out.println(ip);
    }
}
