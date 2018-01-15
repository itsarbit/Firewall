import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class Firewall {
  // DELIMINITER is used for range.
  private static String DELIMINITER = "-";
  // set is used to store the key of iptable. It allows us to find accept
  // packet with O(1) time.
  private static Set<String> set = null;
  // NOTE: the following map can be used as the supported direction and
  // protocol. Also it allows the generated key to be shorten
  private static Map<String, Integer> dirMap = null;
  private static Map<String, Integer> protocolMap = null;

  // Firewall instantiate the Firewall class and load iptable to given
  // hashset. My implementation and work load is mainly here becuase this is a
  // one time job.
  public Firewall(String file) throws FileNotFoundException{
    // initiate a firewall set to store
    set = new HashSet<>();
    dirMap = new HashMap<>();
    dirMap.put("inbound", 0);
    dirMap.put("outbound", 1);
    protocolMap = new HashMap<>();
    protocolMap.put("tcp", 0);
    protocolMap.put("udp", 1);
    //read csv line by line, ref: Stackoverflow
    try(BufferedReader br = new BufferedReader(new FileReader(file))) {
      for(String line; (line = br.readLine()) != null;) {
        // direction, protocol, port [range], IP [range]
        String[] cells = line.split(",");
        String portString = cells[2];
        String ipString = cells[3];
        int portMin = 1;
        int portMax = 65535;
        long ipMin = hashIP("0.0.0.0");
        long ipMax = hashIP("255.255.255.255");
        try {
          // handle port
          if (portString.contains(DELIMINITER)) {
            String[] splitPort = portString.split(DELIMINITER);
            // TODO: what if left is larger than right?
            portMin = Math.max(Integer.parseInt(splitPort[0]), portMin);
            portMax = Math.min(Integer.parseInt(splitPort[1]), portMax);
          } else {
            portMin = portMax = Integer.parseInt(portString);
          }

          // handle ip
          if (ipString.contains(DELIMINITER)) {
            String[] splitIP = ipString.split(DELIMINITER);
            // TODO: what if left is larger than right?
            ipMin = Math.max(ipMin, hashIP(splitIP[0]));
            ipMax = Math.min(ipMax, hashIP(splitIP[1]));
          } else {
            ipMin = ipMax = hashIP(ipString);
          }
        } catch (Exception e) {

          e.printStackTrace();
        }
        for (int p = portMin; p <= portMax; p++) {
          for (long i = ipMin; i <= ipMax; i++) {
            // direction, protocol, port, IP
            set.add(keyGen(cells[0], cells[1], p, i));
          }
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  // acceptPacket allows users to check if the the given setting is in the
  // iptable.
  public boolean acceptPacket(String direction, String protocol, int port, String IP) {
    return set.contains(keyGen(direction, protocol, port, hashIP(IP)));
  }

  // NOTE: this is only work in IPv4
  private long hashIP(String IP) {
    String[] classes = IP.split("\\.");
    // one class only contains 0-255
    long ans = 0;
    for (int i = 0; i < 4; i++) {
      ans = ans * 256 + Long.parseLong(classes[i]);
    }
    return ans;
  }

  // TODO: enhance performance by shorten the key length
  private String keyGen(String direction, String protocol, int port, long hashIP) {
    // FIXME:TODO: check before get to make sure give dir/protocol is in the
    // map, if no, return some errors.
    return dirMap.get(direction) + ";" + protocolMap.get(protocol) + ";" +
      String.valueOf(hashIP) + ";" + port;
  }

  public static void main(String[] args) {
    try {
      // TODO: maybe allow user System in or args to input the file path.
      Firewall fw = new Firewall("../resources/iptable.csv");
      // match first rule
      boolean ok = fw.acceptPacket("inbound", "tcp", 80, "192.168.1.2");
      System.out.println(ok);
      // match second rule
      ok = fw.acceptPacket("outbound", "udp", 10234, "192.168.10.11");
      System.out.println(ok);
      // match third rule
      ok = fw.acceptPacket("inbound", "udp", 53, "192.168.2.1");
      System.out.println(ok);
      // match fourth rule
      ok = fw.acceptPacket("outbound", "udp", 2000, "52.12.48.92");
      System.out.println(ok);
      // match fifth rule
      ok = fw.acceptPacket("inbound", "tcp", 2344, "123.45.66.255");
      System.out.println(ok);
      boolean nok = fw.acceptPacket("inbound", "tcp", 81, "192.168.1.2");
      System.out.println(nok);
      nok = fw.acceptPacket("inbound", "tcp", 10234, "192.168.10.11");
      System.out.println(nok);
      nok = fw.acceptPacket("outbound","udp", 2001,"52.12.48.92");
      System.out.println(nok);
      nok = fw.acceptPacket("inbound","tcp",2255, "123.45.6.77");
      System.out.println(nok);
      nok = fw.acceptPacket("inbound","tcp",0, "123.45.6.77");
      System.out.println(nok);
      nok = fw.acceptPacket("inbound","tcp",65535, "123.45.6.77");
      System.out.println(nok);
      nok = fw.acceptPacket("inbound","tcp",123, "255.255.255.255");
      System.out.println(nok);
    }catch (FileNotFoundException e) {
      e.printStackTrace();
    }
  }
}
