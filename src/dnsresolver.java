import org.xbill.DNS.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class dnsresolver {

    List<String> rootservers;
    InetAddress myBindAddr;

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
        try {
            myBindAddr = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        System.out.println("Mine: "+myBindAddr.getHostAddress());
    }

    public void resolveQuery(String query) throws Exception {
        String inputString = query;
        if(inputString.contains("http")){
            //inputString = query.substring(8,query.length());
            inputString = query.split("//")[1];
            System.out.println("query trimmed to "+inputString);
        }

        if(inputString.contains("www")){
            inputString = query.split("www.")[1];
            System.out.println("query trimmed to "+inputString);
        }

        // at this point we have site name and domain only

        SimpleResolver resolver = new SimpleResolver(rootservers.get(0));
        resolver.setTCP(true);
       // resolver.setLocalAddress(InetAddress.getByName(InetAddress.getLocalHost().getHostAddress()));
        Record rec = Record.newRecord(Name.fromString(inputString),Type.A,DClass.IN);
        Message msg = Message.newQuery(rec);
        Message recv = resolver.send(msg);
        if(recv != null) {
            System.out.println(recv);
            resolver = new SimpleResolver("192.5.6.30");
            resolver.setTCP(true);
            // resolver.setLocalAddress(InetAddress.getByName(InetAddress.getLocalHost().getHostAddress()));
            rec = Record.newRecord(Name.fromString("stonybrook."),Type.A,DClass.IN);
            msg = Message.newQuery(rec);
            recv = resolver.send(msg);
            if(recv != null){
                System.out.println(recv);
            }
        }
        System.out.println("Sent");
    }

    public static void main(String args[]){
        System.out.println("Hello");
        dnsresolver resolver = new dnsresolver();
        try {
            //resolver.resolveQuery("http://www.google.com");
            //resolver.resolveQuery("https://www.facebook.com");
            resolver.resolveQuery("https://cs.stonybrook.edu.");


        } catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }
}
