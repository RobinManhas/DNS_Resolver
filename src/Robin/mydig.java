package Robin;

public class mydig {
    public static void main(String args[]){
        if(args.length == 2){
            dnsresolver resolver = new dnsresolver();
            resolver.main(args);
        }
        else if(args.length == 3 && args[2].equalsIgnoreCase("+dnssec")){
            dnssecresolver resolver = new dnssecresolver();
            resolver.main(args);
        }
    }
}
