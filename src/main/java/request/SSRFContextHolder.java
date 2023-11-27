package request;

import com.alibaba.jvm.sandbox.api.listener.ext.Advice;

import java.util.ArrayList;

public class SSRFContextHolder {
    private static ThreadLocal<SSRFContextHolder.Context> SSRF_THREAD_LOCAL = new InheritableThreadLocal<>();

    public static SSRFContextHolder.Context getContext() {
        return SSRF_THREAD_LOCAL.get();
    }

    public static void remove() {
        SSRF_THREAD_LOCAL.remove();
    }

    public static void set(SSRFContextHolder.Context context) {
        SSRF_THREAD_LOCAL.set(context);
    }


    /**
     * ssrf hook 点上下文
     */
    public static class Context {
        private ArrayList<Advice> advices;
        private ArrayList<String> classNames;

        public Context() {
            advices = new ArrayList<>();
            classNames = new ArrayList<>();
        }

        public Object[] getAdvices() {
            return new Object[]{classNames, advices};
        }

        public void setAdvices(Advice advice) {
            this.advices.add(advice);
        }

        public void setClassNames(String className) {
            this.classNames.add(className);
        }
    }
}
