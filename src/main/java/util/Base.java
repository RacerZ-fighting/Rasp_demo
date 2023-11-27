package util;

import com.google.gson.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Iterator;

public class Base {
    public static HashSet<String[]> getBase() throws FileNotFoundException {
        FileReader reader = new FileReader("C:\\Users\\lenovo\\Desktop\\作品赛\\RASP_PLUS\\src\\main\\resources\\SSRF\\SSRF.json");
        JsonElement root = null;
        HashSet<String[]> set = new HashSet<>();

        try {

            root = JsonParser.parseReader(reader);

            if (root != null) {
                JsonObject jsonObject = root.getAsJsonObject();
                // arr1
                JsonArray arr1 = jsonObject.getAsJsonArray("segments");
                if (arr1 != null) {
                    for (JsonElement element : arr1) {
                        JsonObject obj1 = element.getAsJsonObject();
                        // arr2
                        JsonObject obj0 = obj1.getAsJsonObject("start");
                        JsonObject obj00 = obj1.getAsJsonObject("end");

                        String className1 = obj0.getAsJsonObject("properties").get("CLASSNAME").getAsString();
                        String methodName1 = obj0.getAsJsonObject("properties").get("NAME").getAsString();
                        String SIGNATURE1 = obj0.getAsJsonObject("properties").get("SIGNATURE").getAsString();

                        String className2 = obj00.getAsJsonObject("properties").get("CLASSNAME").getAsString();
                        String methodName2 = obj00.getAsJsonObject("properties").get("NAME").getAsString();
                        String SIGNATURE2 = obj00.getAsJsonObject("properties").get("SIGNATURE").getAsString();

                        set.add(new String[] {className1, methodName1, getParams(SIGNATURE1), SIGNATURE1});
                        set.add(new String[] {className2, methodName2, getParams(SIGNATURE2), SIGNATURE2});


                    }
                }
                /*Iterator<String[]> iterator = set.iterator();
                while (iterator.hasNext()) {
                    String[] ele = iterator.next();

                    System.out.println(ele[2] + "size: " + ele[2].length());
                }*/
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return set;
    }

    public static HashSet<String> getClassNames() throws FileNotFoundException, ClassNotFoundException {
        HashSet<String[]> base = getBase();
        HashSet<String> res = new HashSet<>();

        Iterator<String[]> iterator = base.iterator();
        while (iterator.hasNext()) {
            String className = iterator.next()[0];
            // Class<?> clazz = Class.forName(className);
            // if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
            //     res.add(className);
            // }
            res.add(className);
        }

        return res;
    }

    public static HashSet<String> getMethodNames() throws FileNotFoundException {
        HashSet<String[]> base = getBase();
        HashSet<String> res = new HashSet<>();

        Iterator<String[]> iterator = base.iterator();
        while (iterator.hasNext()) {
            String methodName = iterator.next()[1];
            res.add(methodName);
        }

        return res;
    }

    public static HashSet<String> getSignature() throws FileNotFoundException {
        HashSet<String[]> base = getBase();
        HashSet<String> res = new HashSet<>();

        Iterator<String[]> iterator = base.iterator();
        while (iterator.hasNext()) {
            String signature = iterator.next()[3];
            res.add(signature);
        }

        return res;
    }

    public static String getParams(String paramStr) {
        int left = paramStr.indexOf("(");
        int right = paramStr.indexOf(")");
        return paramStr.substring(left+1, right);
    }

    public static void main(String[] args) throws FileNotFoundException, ClassNotFoundException {
        HashSet<String> base = Base.getSignature();
        Iterator<String> iterator = base.iterator();
        while (iterator.hasNext()) {
            String next = iterator.next();
            System.out.println(next);
        }
    }

}
