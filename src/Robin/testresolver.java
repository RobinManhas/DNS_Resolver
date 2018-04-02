package Robin;

public class testresolver {
    public static void main(String args[]){
        dnsresolver resolver = new dnsresolver();
        String[] arr = new String[3];

        System.out.println("==============================================================");
        arr[0] = "mydig";
        arr[1] = "google.co.jp";
        arr[2] = "A";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "google.co.jp";
        arr[2] = "MX";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "google.co.jp";
        arr[2] = "NS";
        resolver.main(arr);
        System.out.println("==============================================================");

        System.out.println("==============================================================");
        arr[0] = "mydig";
        arr[1] = "google.com";
        arr[2] = "A";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "mail.google.com";
        arr[2] = "MX";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "facebook.com";
        arr[2] = "NS";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "cs.stonybrook.edu";
        arr[2] = "A";
        resolver.main(arr);
        System.out.println("==============================================================");

        arr[0] = "mydig";
        arr[1] = "facebook.com";
        arr[2] = "MX";
        resolver.main(arr);
        System.out.println("==============================================================");
    }
}
