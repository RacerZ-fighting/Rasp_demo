package check;

import org.slf4j.Logger;
import request.OgnlContextHolder;

import java.util.HashMap;

public class OgnlCheck {
    /**
     * OGNL语句黑名单
     */
    private static String[] ognlBlackList = {
            "java.lang.Runtime",
            "java.lang.Class",
            "java.lang.ClassLoader",
            "java.lang.System",
            "java.lang.ProcessBuilder",
            "java.lang.Object",
            "java.lang.Shutdown",
            "ognl.OgnlContext",
            "ognl.TypeConverter",
            "ognl.MemberAccess",
            "_memberAccess",
            "ognl.ClassResolver",
            "java.io.File",
            "javax.script.ScriptEngineManager",
            "excludedClasses",
            "excludedPackageNamePatterns",
            "excludedPackageNames",
            "com.opensymphony.xwork2.ActionContext"
    };

    public static boolean check(String attackType, String systemCommand, Logger log) {
        boolean isBlocked1 = false, isBlocked2 = false;

        OgnlContextHolder.Context ognlContext = OgnlContextHolder.getContext();
        // 1. C 层存在拦截信息
        if (ognlContext != null) {
            // TODO 根据调用堆栈判断属于 Ognl 还是其他
            HashMap<String, Object> map = ognlContext.getMap();
            String expression = (String) map.getOrDefault("expression", "NULL");
            // 检查 Expression 中是否包含 expression 的命令字符串
            if (expression.contains(systemCommand)) {
                isBlocked1 = true;
            }

            String className = (String) map.getOrDefault("className", "NULL");
            String methodName = (String) map.getOrDefault("methodName", "NULL");
            // 检查 ognlRuntime 调用方法是否为黑名单中的类
            for (String s : ognlBlackList) {
                if (className.contains(s)) {
                    isBlocked2 = true;
                }
            }

            // 查到在黑名单中  TODO
            if (isBlocked1 || isBlocked2) {
                log.warn("[warning] RCE Attack!");
                log.warn("[level C]expression in ognl: " + expression);
                log.warn("[level C]method call in ognl: " + className + "#" + methodName);
                log.warn("[level D]evil operation: " + attackType + " => " + systemCommand);
                checkAction(map, log);
                return true;
            }

            checkAction(map, log);
        }

        return false;
    }

    public static void checkAction(HashMap<String, Object> map, Logger log) {
        // 显示 B 层映射的业务逻辑函数
        String actionName = (String) map.get("actionName");
        String actionMethod = (String) map.get("actionMethod");

        log.info("[level B]Behavior occur in " + actionName + "#" + actionMethod);
    }
}
