package server;

import com.alibaba.jvm.sandbox.api.Information;
import com.alibaba.jvm.sandbox.api.Module;
import com.alibaba.jvm.sandbox.api.ModuleLifecycle;
import com.alibaba.jvm.sandbox.api.listener.ext.Advice;
import com.alibaba.jvm.sandbox.api.listener.ext.AdviceListener;
import com.alibaba.jvm.sandbox.api.listener.ext.EventWatchBuilder;
import com.alibaba.jvm.sandbox.api.resource.ModuleEventWatcher;
import config.HookConfig;
import org.kohsuke.MetaInfServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import request.OgnlContextHolder;
import util.Reflection;

import javax.annotation.Resource;
import java.util.HashMap;

@MetaInfServices(Module.class)
@Information(id = "rasp-ognlDispatcher-hook")
public class OgnlDispatcherHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(OgnlDispatcherHook.class);

    public void hookRequest() {

        new EventWatchBuilder(moduleEventWatcher)
                .onClass("com.opensymphony.xwork2.DefaultActionProxy")
                .includeSubClasses()
                .onBehavior("execute")
                .onWatch(new AdviceListener() {
                    @Override
                    protected void before(Advice advice) throws Throwable {

                        Object thisObj = advice.getTarget();
                        Object configObj = Reflection.invokeMethod(thisObj, "getConfig", new Class[]{});
                        String ActionName = (String) Reflection.invokeMethod(configObj, "getClassName", new Class[]{});
                        String ActionMethod = (String) Reflection.invokeMethod(thisObj, "getMethod", new Class[]{});

                        HashMap<String, Object> params = new HashMap<>();
                        params.put("actionName", ActionName);
                        params.put("actionMethod", ActionMethod);

                        OgnlContextHolder.Context context = OgnlContextHolder.getContext();
                        if (context == null) {
                            context = new OgnlContextHolder.Context();
                        }
                        context.setMap(params);
                        OgnlContextHolder.set(context);

                        super.before(advice);
                    }
                });

    }

    @Override
    public void onLoad() throws Throwable {

    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-ognlDispatcher-hook module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-ognlDispatcher-hook module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("ognl")) {
            hookRequest();
            log.info("rasp-ognlDispatcher-hook module load finished");
        }
    }
}
