package config;

import java.net.Socket;
import java.util.HashMap;

public class HookConfig {
    public static HashMap<String,Boolean> hookConfig = new HashMap<String, Boolean>() {
        {
            put("http",true);
            put("rce",true);
            put("ssrf", false);
            put("ognl", true);



            /*put("jni",true);
            put("xxe",true);

            put("sqli",true);
            put("deserialize",true);
            put("ws",true);
            put("dubbo",true);*/
        }
    };

    // 格式 同 tabby 的 signature
    public static HashMap<String, String> hookedMethod = new HashMap<String, String>() {
        {
            // ssrf
            put("<sun.net.www.protocol.http.HttpURLConnection: java.io.InputStream getInputStream()>", "ssrf");

            // command
            put("<java.lang.ProcessImpl: long create(java.lang.String,java.lang.String,java.lang.String,long[],boolean)>", "command");

            // http
            put("<javax.servlet.http.HttpServlet: void service(javax.servlet.ServletRequest,javax.servlet.ServletResponse)>", "http");

            // todo ognl

        }
    };

    public static Boolean isHookedMethod(String HOOKName) {
        return hookedMethod.containsKey(HOOKName);
    }

    public static String getVulType(String HOOKName) { return hookedMethod.get(HOOKName); }

    public static void createHookMethod(String HOOKName, String vulType) {
        hookedMethod.put(HOOKName, vulType);
    }

    public static Boolean isEnable(String hook) {
        return hookConfig.get(hook);
    }

}
