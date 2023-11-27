package request;

import java.util.HashMap;

public class OgnlContextHolder {
    private static ThreadLocal<OgnlContextHolder.Context> OGNL_THREAD_LOCAL = new InheritableThreadLocal<>();

    public static OgnlContextHolder.Context getContext() {
        return OGNL_THREAD_LOCAL.get();
    }

    public static void remove() {
        OGNL_THREAD_LOCAL.remove();
    }

    public static void set(OgnlContextHolder.Context context) {
        OGNL_THREAD_LOCAL.set(context);
    }

    public static class Context {
        private HashMap<String, Object> map;

        public Context() {
            map = new HashMap<>();
        }

        public HashMap<String, Object> getMap() {
            return map;
        }

        public void setMap(HashMap<String, Object> map) {
            this.map = map;
        }
    }
}
