package HOOK.RCE.SSRF;

import com.alibaba.jvm.sandbox.api.Information;
import com.alibaba.jvm.sandbox.api.Module;
import com.alibaba.jvm.sandbox.api.ModuleLifecycle;
import com.alibaba.jvm.sandbox.api.ProcessController;
import com.alibaba.jvm.sandbox.api.listener.ext.Advice;
import com.alibaba.jvm.sandbox.api.listener.ext.AdviceListener;
import com.alibaba.jvm.sandbox.api.listener.ext.Behavior;
import com.alibaba.jvm.sandbox.api.listener.ext.EventWatchBuilder;
import com.alibaba.jvm.sandbox.api.resource.ModuleEventWatcher;
import config.HookConfig;
import org.kohsuke.MetaInfServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import request.HttpRequestContextHolder;
import request.SSRFContextHolder;
import sun.net.www.protocol.http.HttpURLConnection;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.*;

@MetaInfServices(Module.class)
@Information(id = "rasp-ssrf-hook")
public class URLConnectionHook implements Module, ModuleLifecycle {

    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(URLConnectionHook.class);

    public void checkSSRFCommand() {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("sun.net.www.protocol.http.HttpURLConnection")
                .includeBootstrap()
                .onBehavior("getInputStream")
                .onWatch(new URLConnectionHook.WindowsSSRFAdviceListener());
    }

    @Override
    public void onLoad() throws Throwable {

    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-rce-hook module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-rce-hook module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("ssrf")) {
            checkSSRFCommand();
            log.info("rasp-ssrf-hook moudule load finished");
        }
    }

    public static class WindowsSSRFAdviceListener extends AdviceListener {

        public boolean checkCommand(Map params, SSRFContextHolder.Context cotx) {
            boolean flag = true;
            // TODO 添加上下文
            // TODO 1. HTTP 入口上下文
            // TODO Just for Test
            HttpRequestContextHolder.Context context = HttpRequestContextHolder.getContext();
            if (context != null) {
                HttpServletRequest request = context.getRequest();

                URL url = (URL) params.get("url");

                Map<String, String[]> parameterMap = request.getParameterMap();
                String contextPath = request.getContextPath();
                String requestURI = request.getRequestURI();

                // TODO 假定用户仅可从参数输入
                if (parameterMap.isEmpty()) flag = false;

                log.info("[+]user input info: ");
                int k = 1;
                for (Map.Entry<String, String[]> entry : parameterMap.entrySet()){
                    String key = entry.getKey();
                    String[] values = entry.getValue();
                    if (values.length != 0) {
                        log.info("  " + k + ": " + key + " = " + Arrays.toString(values));
                        k ++;
                    }
                }
                log.info("[+]path: " + contextPath + requestURI);

                log.info("[+]hook ip info in HttpURLConnection#getInputStream(): " + url.toString());

            }

            // TODO 2. 关键函数上下文
            Object[] pairs = cotx.getAdvices();
            ArrayList<Advice> advices = (ArrayList<Advice>) pairs[1];
            ArrayList<String> classNames = (ArrayList<String>) pairs[0];

            for (int i = 0; i < advices.size(); i ++) {
                Advice advice = advices.get(i);
                if (advice.hasMark("ssrf")) {

                    Behavior behavior = advice.getBehavior();

                    log.info("[+]ssrf chain: " + classNames.get(i) +  "#" + behavior.getName() + " --> ");

                    log.info("  [*] params: ");
                    if (advice.getParameterArray().length != 0) {
                        Object[] parameterArray = advice.getParameterArray();
                        for (int j = 0; j < parameterArray.length; j ++) {
                            log.info("    " + (j + 1) + ": " + parameterArray[j].toString());
                        }
                    } else {
                        log.info(" null");
                    }

                }
            }

            return flag;
        }

        @Override
        protected void before(Advice advice) throws Throwable {
            log.debug("hook sun.net.www.protocol.http.HttpURLConnection#getInputStream()");

            HashMap<String, Object> params = new HashMap<>();

            // 获取 cmdarray 参数信息
            HttpURLConnection thisObj = (HttpURLConnection) advice.getTarget();
            URL url = thisObj.getURL();
            params.put("url", url);

            // 关联上下文
            SSRFContextHolder.Context context = SSRFContextHolder.getContext();
            if (context != null) {
                // TODO 制订防御策略
                boolean isblocked = checkCommand(params, context);
                if (isblocked) {
                    ProcessController.throwsImmediately(new RuntimeException("evil operation!"));
                }
            }

            ProcessController.noneImmediately();
            super.before(advice);
        }

        /*@Override
        protected void afterThrowing(Advice advice) throws Throwable {
            // 方法调用完成，如果抛出异常（插桩的代码 bug导致的异常或者主动阻断的异常）将清除上下文环境变量
            HttpRequestContextHolder.remove();
            SSRFContextHolder.remove();
        }*/
    }

}

