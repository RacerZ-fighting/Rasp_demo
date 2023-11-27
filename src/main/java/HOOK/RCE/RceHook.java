package HOOK.RCE;

import check.OgnlCheck;
import com.alibaba.jvm.sandbox.api.Information;
import com.alibaba.jvm.sandbox.api.Module;
import com.alibaba.jvm.sandbox.api.ModuleLifecycle;
import com.alibaba.jvm.sandbox.api.ProcessController;
import com.alibaba.jvm.sandbox.api.listener.ext.Advice;
import com.alibaba.jvm.sandbox.api.listener.ext.AdviceListener;
import com.alibaba.jvm.sandbox.api.listener.ext.EventWatchBuilder;
import com.alibaba.jvm.sandbox.api.resource.ModuleEventWatcher;
import config.HookConfig;
import org.kohsuke.MetaInfServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import request.HttpRequestContextHolder;
import util.StackTrace;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@MetaInfServices(Module.class)
@Information(id = "rasp-rce-hook")
public class RceHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final String TYPE = "cmd";

    private static final Logger log = LoggerFactory.getLogger(RceHook.class);

    public void checkRceCommand() {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("java.lang.ProcessImpl")
                .includeBootstrap()
                .onBehavior("create")
                .onWatch(new WindowsCommandAdviceListener());
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
        if (HookConfig.isEnable("rce")) {
            checkRceCommand();
            log.info("rasp-rce-hook moudule load finished");
        }
    }

    public static class WindowsCommandAdviceListener extends AdviceListener {

        public boolean checkCommand(Map params) {
            // 命令参数提取
            String systemCommand = (String) params.get("command");

            // TODO 添加上下文
            // TODO 1. HTTP 入口上下文
            // TODO Just for Test
            HttpRequestContextHolder.Context context = HttpRequestContextHolder.getContext();
            if (context != null) {
                HttpServletRequest request = context.getRequest();

                Map<String, String[]> parameterMap = request.getParameterMap();
                String contextPath = request.getContextPath();
                String requestURI = request.getRequestURI();

                log.info("[level A]user input info: ");
                int k = 1;
                for (Map.Entry<String, String[]> entry : parameterMap.entrySet()){
                    String key = entry.getKey();
                    String[] values = entry.getValue();
                    if (values.length != 0) {
                        log.info("  " + k + ": " + key + " = " + Arrays.toString(values));
                        k ++;
                    }
                }
                log.info("[level A]path: " + contextPath + requestURI);
            }

            // TODO 这里后续可能需要根据调用堆栈判断一下服务环境信息

            // TODO 2. 关键函数上下文 以 ognl 注入为例
            boolean isOgnlAttck = OgnlCheck.check(TYPE, systemCommand, log);

            if (isOgnlAttck) return true;

            return false;
        }

            @Override
            protected void before(Advice advice) throws Throwable {
            log.debug("hook ProcessImpl#create()");

            HashMap<String, Object> params = new HashMap<>();

            // 获取 cmdarray 参数信息
            String cmdarray = (String) advice.getParameterArray()[0];
            params.put("command", cmdarray);


            // 获取 envblock 参数信息
            String envBlock = (String) advice.getParameterArray()[1];
            LinkedList<String> envList = new LinkedList<>();
            if (envBlock != null) {
                int index = -1;
                for (int i = 0; i < envBlock.length(); i++) {
                    if (envBlock.charAt(i) == '\0') {
                        String envItem = envBlock.substring(index + 1, i);
                        if (envItem.length() > 0) {
                            envList.add(envItem);
                        }
                    }
                    index = i;
                }
            }
            params.put("env", envList);
            // 获取堆栈信息
            String[] stackTraceString = StackTrace.getStackTraceString();
            LinkedList<String> stackInfo = new LinkedList<>();
            Collections.addAll(stackInfo, stackTraceString);
            params.put("stack", stackInfo);

            // TODO 制订防御策略
            boolean isblocked = checkCommand(params);

            ProcessController.throwsImmediately(new RuntimeException("evil operation!"));
            super.before(advice);
        }
    }
}

