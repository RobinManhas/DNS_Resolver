package Robin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

public class digTest {

    public static void main(String[] a)throws IOException {
        int MAX = 7;
        String[][]input = new String[MAX][2];
//        input[0]=new String[]{"Google.com","A"};
//        input[1]=new String[]{"Youtube.com","A"};
//        input[2]=new String[]{"Facebook.com","A"};
//        input[3]=new String[]{"Google.co.uk","A"};
//        input[4]=new String[]{"Wikipedia.org","A"};
//        input[5]=new String[]{"Reddit.com","A"};
//        input[6]=new String[]{"Yahoo.com","A"};
//        input[7]=new String[]{"Google.co.in","A"};
//        input[8]=new String[]{"Google.com.br","A"};
//        input[9]=new String[]{"Taobao.com","A"};
//        input[10]=new String[]{"Amazon.com","A"};
//        input[11]=new String[]{"Tmall.com","A"};
//        input[12]=new String[]{"Twitter.com","A"};
//        input[13]=new String[]{"Google.co.jp","A"};
//        input[14]=new String[]{"Live.com","A"};
//        input[15]=new String[]{"Instagram.com","A"};
//        input[16]=new String[]{"Vk.com","A"};
//        input[17]=new String[]{"Google.de","A"};
        input[8]=new String[]{"Jd.com","A"};
        input[0]=new String[]{"Weibo.com","A"};
        input[2]=new String[]{"Sina.com.cn","A"};
        input[3]=new String[]{"Sohu.com","A"};
        input[4]=new String[]{"Baidu.com","A"};
        input[5]=new String[]{"Qq.com","A"};
        input[6]=new String[]{"360.cn","A"};

        long[] mydigAVG = new long[MAX];
        int[] localDNSAVG = new int[MAX];
        int[] googleDNSAVG = new int[MAX];
        int i =0;
        System.out.println("Command\t\ttype\tMydig\tlocal DNS\tgoogle DNS");
        for(String[] args: input){
            if(args[0] == null)
                break;
            long mydigTotal =0;
            int localTotal =0;
            int googleTotal =0;
            for(int count = 0;count<30; count++){
                //mydigTotal = dnsresolver.main(args);
                localTotal = executeCmd(args, true);
                googleTotal = executeCmd(args, false);
                System.out.println(args[0]+","+args[1]+","+mydigTotal+","+localTotal+","+googleTotal);
            }
            mydigAVG[i] = mydigTotal/10;
            localDNSAVG[i] = localTotal/10;
            googleDNSAVG[i] = googleTotal/10;
            i++;
        }

        //executeCmd(input[0], false);





    }

    private static int  executeCmd(String[] args, boolean isLocal){
        try {
            String cmd ="dig ";
            if(!isLocal){
                cmd +="@8.8.8.8 ";
            }
            cmd += args[0]+" "+args[1];
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line = "";
            while ((line = reader.readLine())!= null) {
                sb.append(line + "\n");
                if(line.contains("Query time")){
                    String time = (((line.split(":")[1]).trim()).split(" "))[0];
                    //System.out.println("time: "+ time);
                    return Integer.valueOf(time);
                }
            }
            //System.out.println(sb.toString());
        }catch(InterruptedException | IOException e){
            //System.out.println("dig command interrupted");
        }
        return 0;
    }

}