package HOOK.RCE.OGNL;

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
import request.OgnlContextHolder;
import util.StackTrace;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;

/*
*   用于分析 ognl 表达式的方法调用
* */
@MetaInfServices(Module.class)
@Information(id = "rasp-ognl-hook1")
public class OgnlRuntimeHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(OgnlRuntimeHook.class);

    @Override
    public void onLoad() throws Throwable {

    }

    public void getRuntimeHook() {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("ognl.OgnlRuntime")
                .includeBootstrap()
                .onBehavior("callAppropriateMethod")
                .onWatch(new OGNLRuntimeAdviceListener());
    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-ognl-hook1 module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-ognl-hook1 module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("ognl")) {
            getRuntimeHook();
            log.info("ognl-rce-hook1 moudule load finished");
        }
    }

    public static class OGNLRuntimeAdviceListener extends AdviceListener {

        @Override
        protected void before(Advice advice) throws Throwable {
            log.debug("hook OgnlRuntime#callAppropriateMethod()");

            HashMap<String, Object> params = new HashMap<>();

            // 获取 target 和 methodName
            Object[] parameterArray = advice.getParameterArray();
            String className = parameterArray[1].getClass().getName();
            String methodName = (String) parameterArray[3];
            params.put("className", className);
            params.put("methodName", methodName);

            // 获取堆栈信息
            // String[] stackTraceString = StackTrace.getStackTraceString();
            // LinkedList<String> stackInfo = new LinkedList<>();
            // Collections.addAll(stackInfo, stackTraceString);
            // params.put("stack", stackInfo);

            OgnlContextHolder.Context context = OgnlContextHolder.getContext();
            if (context == null) {
                context = new OgnlContextHolder.Context();
            }
            HashMap<String, Object> map = context.getMap();
            map.putAll(params);
            OgnlContextHolder.set(context);

            ProcessController.noneImmediately();
            super.before(advice);
        }


    }

}
