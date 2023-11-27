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

import java.util.*;

@MetaInfServices(Module.class)
@Information(id = "rasp-ognl-hook")
public class OgnlExpressionHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(OgnlExpressionHook.class);

    @Override
    public void onLoad() throws Throwable {

    }

    public void getExpressionHook() {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("ognl.OgnlParser")
                .includeBootstrap()
                .onBehavior("topLevelExpression")
                .onWatch(new OGNLAdviceListener());
    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-ognl-hook module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-ognl-hook module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("ognl")) {
            getExpressionHook();
            log.info("ognl-rce-hook moudule load finished");
        }
    }

    public static class OGNLAdviceListener extends AdviceListener {

        @Override
        protected void afterReturning(Advice advice) throws Throwable {
            log.debug("hook OgnlParser#topLevelExpression()");

            HashMap<String, Object> params = new HashMap<>();

            // 获取 expression
            Object returnObj = advice.getReturnObj();
            if (returnObj != null)
            {
                String expression = String.valueOf(returnObj);
                // log.info("[*]expression: " + expression);
                params.put("expression", expression);
            }

            // 获取堆栈信息
            String[] stackTraceString = StackTrace.getStackTraceString();
            LinkedList<String> stackInfo = new LinkedList<>();
            Collections.addAll(stackInfo, stackTraceString);
            params.put("stack", stackInfo);

            OgnlContextHolder.Context context = OgnlContextHolder.getContext();
            if (context == null) {
                context = new OgnlContextHolder.Context();
            }
            // TODO
            HashMap<String, Object> map = context.getMap();
            map.putAll(params);
            OgnlContextHolder.set(context);

            ProcessController.noneImmediately();
            super.afterReturning(advice);
        }


    }

}
