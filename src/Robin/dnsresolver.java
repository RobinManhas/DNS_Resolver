package Robin;

import org.xbill.DNS.*;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.*;

public class dnsresolver {

    List<String> rootservers;
    long querytime;

    /* Initializes with IP address of 13 root servers
    Data courtesy: https://www.iana.org/domains/root/servers */
    public void initializeRootServers(){
        rootservers = new ArrayList<String>();
        rootservers.add("198.41.0.4");
        rootservers.add("199.9.14.201");
        rootservers.add("192.33.4.12");
        rootservers.add("199.7.91.13");
        rootservers.add("192.203.230.10");
        rootservers.add("192.5.5.241");
        rootservers.add("192.112.36.4");
        rootservers.add("198.97.190.53");
        rootservers.add("192.36.148.17");
        rootservers.add("192.58.128.30");
        rootservers.add("193.0.14.129");
        rootservers.add("199.7.83.42");
        rootservers.add("202.12.27.33");
    }

    public dnsresolver(){
        initializeRootServers();
        querytime = 0;
    }

    /*
     * Function: dnsMessageGenerator().
     * Return type: Message
     * This function is used for sending a dnsSec query to the host server.
     * it creates an object of SimpleResolver to send a request and returns the "Message" response received.
     * */
    public Message dnsMessageGenerator(String hname, String inputString, int type) throws Exception{
        long start = System.currentTimeMillis();
        SimpleResolver resolver = new SimpleResolver(hname);
        Record rec = Record.newRecord(Name.fromString(inputString),type,DClass.IN);
        Message msg = Message.newQuery(rec);
        Message recv = resolver.send(msg);
        querytime += (System.currentTimeMillis() - start);
        return recv;
    }

    /*
        Function: dnsQueryResolver
        Return type: Message
        This is the core function that takes in query and type and resolves the query one zone at a time.
        It checks if we have received the answer to query posted to the domain server. If yes, it returns the result
        to the controller, else it further resolves the received result (in case CNAME/ NS records that require further resolving).
     */
    public Message dnsQueryResolver(String query, int type) throws IOException {
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
        for(String roots : rootservers)
        { // for each rootserver
            boolean keepTryingRoot = false;
            nameServerList.add(roots);
            while(nameServerList.size() > 0)
            {
                String hostName = nameServerList.get(0);
                Message recv = null;
                try {
                    recv = dnsMessageGenerator(hostName,inputString, type);
                } catch (java.net.SocketTimeoutException e) {
                    if(nameServerList.size() > 1){
                        nameServerList.remove(0);
                        continue;
                    }
                    else{
                        keepTryingRoot = true;
                        nameServerList.clear();
                        break;
                    }

                }
                catch (Exception e){
                    keepTryingRoot = true;
                    nameServerList.remove(0);
                    break;
                }

                // check if received message is valid
                if(recv.getHeader().getRcode() == Rcode.NOERROR)
                {
                   System.out.println(recv);

                    // now parse all records to get new hostname
                    Record[] answerRec = recv.getSectionArray(Section.ANSWER);
                    if(answerRec.length > 0)
                    {
                        switch(answerRec[0].getType()){
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
                                Message cnameRecv = dnsQueryResolver(answerRec[0].rdataToString(),type);
                                return cnameRecv;
                            }
                        }

                    }
                    else if(recv.getSectionArray(Section.ADDITIONAL).length > 0)
                    {
                        // try from authority
                        nameServerList.clear();
                        Record[] additionalrecord = recv.getSectionArray(Section.ADDITIONAL);
                        for(Record addrecords : additionalrecord){
                            if(addrecords.getType() == Type.A)
                                nameServerList.add(addrecords.rdataToString());
                        }
                    }
                    else if(recv.getSectionArray(Section.AUTHORITY).length > 0)
                    {
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
                            nameServerList.clear();
                            Message nsresp = dnsQueryResolver(authorityrecord[0].rdataToString(),Type.A);
                            //MessageBox(nsresp.toString());
                            if(nsresp.getSectionArray(Section.ANSWER).length > 0)
                            {
                                Record[] respanswrec = nsresp.getSectionArray(Section.ANSWER);
                                for(Record respansw : respanswrec){
                                    if(respansw.getType() == Type.A)
                                        nameServerList.add(respansw.rdataToString());
                                }
                            }
                            if(nsresp.getSectionArray(Section.ADDITIONAL).length > 0)
                            {
                                Record[] respaddrec = nsresp.getSectionArray(Section.ADDITIONAL);
                                for(Record respadd : respaddrec){
                                    if(respadd.getType() == Type.A)
                                        nameServerList.add(respadd.rdataToString());
                                }
                            }
                        }

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
     * Function : dnsController
     * Return type: long (return time taken by query)
     * This is a controller function for dns resolver that provides the statistics such as time taken by the query to run.
     * It is also responsible for finally printing the output of the mydig (similar to requested in assignment).
     */
    public long dnsController(String query, int type) throws Exception {
        long start= System.currentTimeMillis();
        Message ret = dnsQueryResolver(query, type);
        long total = System.currentTimeMillis() - start;
        if(ret == null)
        {
            MessageBox("Error: Could not resolve or no such query: "+query);
            return 0;
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

    // ************************************************** DNSSec *************************************************** //

    public static void main(String args[]){
        if(args.length < 2){
            System.out.println("Invalid input size to dns resolver: "+args.length);
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
        //System.out.println("Input add: "+input+" ,type: "+type);
        dnsresolver resolver = new dnsresolver();
        try {
            resolver.dnsController(input,type);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }

    public void MessageBox(String ip){

        System.out.println(ip);
    }
}
