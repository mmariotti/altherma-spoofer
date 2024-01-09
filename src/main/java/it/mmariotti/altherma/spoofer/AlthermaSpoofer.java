package it.mmariotti.altherma.spoofer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.eclipse.paho.client.mqttv3.MqttAsyncClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import one.util.streamex.EntryStream;
import one.util.streamex.StreamEx;


/**
 * The Class AlthermaSpoofer.
 *
 * @author Michele Mariotti
 */
public class AlthermaSpoofer
{
    /** The Constant ANSWER_ERROR. */
    private static final byte[] PAYLOAD_ERROR = {0x15, (byte) 0xEA};

    /** The mqtt client. */
    private MqttAsyncClient mqttClient;

    /** The server socket. */
    private ServerSocket serverSocket;

    /** The executor. */
    private ExecutorService executor;

    /** The buf. */
    byte[] buf = new byte[256];

    /** The register cache. */
    private ConcurrentNavigableMap<Integer, byte[]> registerCache;

    /** The spoof map. */
    private ConcurrentNavigableMap<Integer, List<Integer>> spoofMap;

    /** The spoof path. */
    private Path spoofPath;

    /** The data path. */
    private Path dataPath;


    /**
     * The main method.
     *
     * @param  args      the arguments
     * @throws Exception the exception
     */
    @SuppressWarnings("unused")
    public static void main(String[] args) throws Exception
    {
        new AlthermaSpoofer();
    }

    /**
     * Instantiates a new altherma spoofer.
     *
     * @throws Exception the exception
     */
    public AlthermaSpoofer() throws Exception
    {
        Properties props = new Properties();
        try(InputStream in = AlthermaSpoofer.class.getResourceAsStream("/config.properties"))
        {
            props.load(in);
        }

        boolean mqttEnabled = Boolean.parseBoolean(props.getProperty("mqtt"));
        String mqttUrl = props.getProperty("mqtt_url");
        String mqttUser = props.getProperty("mqtt_user");
        String mqttPass = props.getProperty("mqtt_pass");
        int listenPort = Integer.parseInt(props.getProperty("listen_port"));

        executor = Executors.newCachedThreadPool();
        registerCache = new ConcurrentSkipListMap<>();

        WatchService watchService = FileSystems.getDefault().newWatchService();

        if(mqttEnabled)
        {
            String clientId = InetAddress.getLocalHost().getHostName() + "-spoofer";
            mqttClient = new MqttAsyncClient(mqttUrl, clientId);

            MqttConnectOptions options = new MqttConnectOptions();
            options.setAutomaticReconnect(true);
            options.setCleanSession(false);
            options.setConnectionTimeout(10);
            options.setUserName(mqttUser);
            options.setPassword(mqttPass.toCharArray());

            mqttClient.connect(options).waitForCompletion(10000);

            mqttClient.subscribe("espaltherma/log", 0, this::mqttHandle);

            System.out.printf("mqtt client connected: url=[%s], clientId=[%s]\n", mqttUrl, clientId);

            spoofMap = new ConcurrentSkipListMap<>();
            spoofPath = Paths.get(props.getProperty("mqtt_spoof_file"));

            loadSpoofMap();

            Path dir = spoofPath.getParent();
            dir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

            executor.execute(() -> pollSpoof(watchService));
        }
        else
        {
            dataPath = Paths.get(props.getProperty("standalone_data_file"));

            loadData();

            Path dir = dataPath.getParent();
            dir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

            executor.execute(() -> pollData(watchService));
        }

        serverSocket = new ServerSocket(listenPort);

        while(true)
        {
            System.out.println("socket accepting...");
            Socket s = serverSocket.accept();

            System.out.println("socket connected");
            executor.submit(() -> accept(s));
        }
    }


    /**
     * Handle.
     *
     * @param topic the topic
     * @param msg   the msg
     */
    private void mqttHandle(String topic, MqttMessage msg)
    {
        try
        {
            String payload = new String(msg.getPayload());

            if(payload.startsWith("0x40 "))
            {
                String register = payload.substring(5, 9);

                String line = DateFormatUtils.format(new Date(), "yyyy-MM-dd HH:mm:ss") + " " + payload + "\n";
                FileUtils.write(new File("work/altherma_mqtt_" + register + ".log"), line, StandardCharsets.UTF_8, true);

                int registerInt = Integer.decode(register);
                String[] tokens = StringUtils.splitPreserveAllTokens(payload.strip().trim());

                byte[] bytes = StreamEx.of(tokens)
                    .mapToInt(Integer::decode)
                    .toByteArray();

                System.out.println("mqtt-bin  : " + hex(bytes));

                List<Integer> spoofList = spoofMap.get(registerInt);
                if(spoofList != null && !spoofList.isEmpty())
                {
                    EntryStream.of(spoofList)
                        .nonNullValues()
                        .forKeyValue((k, v) -> bytes[k + 3] = v.byteValue());

                    bytes[bytes.length - 1] = getCRC(bytes, 0, bytes.length - 1);
                }

                registerCache.put(registerInt, bytes);
                System.out.println("mqtt-spoof: " + hex(bytes));
                System.out.println();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Accept.
     *
     * @param s the s
     */
    private void accept(Socket s)
    {
        while(s.isConnected())
        {
            try
            {
                int n = s.getInputStream().readNBytes(buf, 0, 1);
                if(n < 1)
                {
                    throw new IOException("invalid read");
                }

                int len = s.getInputStream().readNBytes(buf, 1, buf[0]);
                if(len < buf[0])
                {
                    throw new IOException("invalid read");
                }

                System.out.println("Q: " + hex(buf, 0, len + 1) + " (reg: " + hex(buf[2]) + ")");

                byte[] payload = null;
                if(buf[0] == 0x03 && buf[1] == 0x40)
                {
                    Integer register = (int) buf[2];
                    payload = getPayload(register);
                }
                else
                {
                    payload = PAYLOAD_ERROR;
                }

                System.out.println("A: " + hex(payload));
                System.out.println();

                s.getOutputStream().write(payload);
            }
            catch(Exception e)
            {
                e.printStackTrace();
                IOUtils.closeQuietly(s);
                return;
            }
        }
    }

    /**
     * Poll spoof.
     *
     * @param ws the ws
     */
    public void pollSpoof(WatchService ws)
    {
        while(true)
        {
            try
            {
                WatchKey key = ws.take();

                Thread.sleep(50);

                List<WatchEvent<?>> events = key.pollEvents();
                key.reset();

                Path dir = (Path) key.watchable();

                boolean load = StreamEx.of(events)
                    .map(x -> x.context())
                    .select(Path.class)
                    .map(dir::resolve)
                    .anyMatch(spoofPath::equals);

                if(load)
                {
                    loadSpoofMap();
                }
            }
            catch(Exception e)
            {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    /**
     * Load spoof map.
     *
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public void loadSpoofMap() throws IOException
    {
        try(Stream<String> lines = Files.lines(spoofPath))
        {
            StreamEx.of(lines)
                .skip(1)
                .filter(StringUtils::isNotBlank)
                .map(StringUtils::split)
                .mapToEntry(x -> Integer.parseUnsignedInt(x[0], 16), x -> StreamEx.of(x)
                    .skip(1)
                    .map(y -> "--".equals(y) ? null : Integer.parseUnsignedInt(y, 16))
                    .toList())
                .forKeyValue(spoofMap::put);
        }

        System.out.println("spoofMap updated");
        spoofMap.forEach((k, v) -> System.out.println(hex(k) + " => " + StreamEx.of(v)
            .map(x -> x == null ? "--" : hex(x))
            .joining(" ")));
        System.out.println();
    }


    /**
     * Poll data.
     *
     * @param ws the ws
     */
    public void pollData(WatchService ws)
    {
        while(true)
        {
            try
            {
                WatchKey key = ws.take();

                Thread.sleep(50);

                List<WatchEvent<?>> events = key.pollEvents();
                key.reset();

                Path dir = (Path) key.watchable();

                boolean load = StreamEx.of(events)
                    .map(x -> x.context())
                    .select(Path.class)
                    .map(dir::resolve)
                    .anyMatch(dataPath::equals);

                if(load)
                {
                    loadData();
                }
            }
            catch(Exception e)
            {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    /**
     * Load data.
     *
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public void loadData() throws IOException
    {
        try(Stream<String> lines = Files.lines(dataPath))
        {
            StreamEx.of(lines)
                .skip(1)
                .filter(StringUtils::isNotBlank)
                .remove(x -> x.startsWith("#"))
                .map(StringUtils::split)
                .mapToEntry(x -> Integer.parseUnsignedInt(x[0], 16), x ->
                {
                    byte[] bytes = StreamEx.of(x)
                        .skip(1)
                        .mapToInt(y -> Integer.parseUnsignedInt(y, 16))
                        .append(0)
                        .toByteArray();

                    bytes[bytes.length - 1] = getCRC(bytes, 0, bytes.length - 1);

                    return bytes;
                })
                .forKeyValue(registerCache::put);
        }

        System.out.println("registerCache updated");
        registerCache.forEach((k, v) -> System.out.println(hex(k) + " => " + hex(v)));
        System.out.println();
    }

    /**
     * Gets the payload.
     *
     * @param  register the register
     * @return          the payload
     */
    private byte[] getPayload(Integer register)
    {
        byte[] payload = registerCache.get(register);
        if(payload == null)
        {
            return PAYLOAD_ERROR;
        }

        return payload;
    }

    /**
     * Gets the crc.
     *
     * @param  src the src
     * @param  off the off
     * @param  len the len
     * @return     the crc
     */
    public static byte getCRC(byte[] src, int off, int len)
    {
        byte b = 0;
        for(int i = 0; i < len; i++)
        {
            b += src[i + off];
        }
        return (byte) ~b;
    }

    /**
     * Hex.
     *
     * @param  array the array
     * @return       the string
     */
    public static String hex(byte[] array)
    {
        return hex(array, 0, array.length);
    }

    /**
     * Hex.
     *
     * @param  array  the array
     * @param  offset the offset
     * @param  length the length
     * @return        the string
     */
    public static String hex(byte[] array, int offset, int length)
    {
        return hex(array, offset, length, true, null, ":");
    }

    /**
     * Hex.
     *
     * @param  array     the array
     * @param  offset    the offset
     * @param  length    the length
     * @param  uppercase the uppercase
     * @param  prefix    the prefix
     * @param  separator the separator
     * @return           the string
     */
    public static String hex(byte[] array, int offset, int length, boolean uppercase, String prefix, String separator)
    {
        if(array == null)
        {
            return null;
        }

        if(length == 0)
        {
            return "";
        }

        boolean p = prefix != null && !prefix.isEmpty();
        boolean s = separator != null && !separator.isEmpty();

        int len = (prefix != null ? prefix.length() : 0) * length + 2 * length + (separator != null ? separator.length() : 0) * (length - 1);

        StringBuilder builder = new StringBuilder(len);

        for(int i = offset; i < length; i++)
        {
            byte num = array[i];
            char c1 = Character.forDigit(num >> 4 & 0xF, 16);
            char c2 = Character.forDigit(num & 0xF, 16);

            if(p)
            {
                builder.append(prefix);
            }

            builder.append(uppercase ? Character.toUpperCase(c1) : c1);
            builder.append(uppercase ? Character.toUpperCase(c2) : c2);

            if(s && i < length - 1)
            {
                builder.append(separator);
            }
        }

        return builder.toString();
    }

    /**
     * Hex.
     *
     * @param  n the n
     * @return   the string
     */
    public static String hex(int n)
    {
        return String.format("%02X", n);
    }

    /**
     * Hex.
     *
     * @param  n the n
     * @return   the string
     */
    public static String hex(byte n)
    {
        return String.format("%02X", n);
    }
}
