package HOOK.RCE.SSRF;

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
import request.SSRFContextHolder;
import util.Base;
import util.Reflection;

import javax.annotation.Resource;
import java.io.FileNotFoundException;
import java.util.*;

@MetaInfServices(Module.class)
@Information(id = "rasp-ssrf-context-hook")
public class SSRFContextHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(SSRFContextHook.class);

    public void checkSSRFContext() throws FileNotFoundException {
        // TODO 按照 vulType 进行获取
        HashSet<String[]> base = Base.getBase();
        Iterator<String[]> iterator = base.iterator();

        while (iterator.hasNext()) {
            String[] e = iterator.next();
            String signature = e[3];
            if (HookConfig.isHookedMethod(signature)) {
                continue;
            }

            String className = e[0];
            String MethodName = e[1];
            // TODO 未判断描述符信息
            new EventWatchBuilder(moduleEventWatcher)
                    .onClass(className)
                    .includeBootstrap() // check
                    .onBehavior(MethodName)
                    .onWatch(new SSRFContextAdviceListener(className));

        }
    }

    @Override
    public void onLoad() throws Throwable {

    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-ssrf-context-hook module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-ssrf-context-hook module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("ssrf")) {
            try {
                checkSSRFContext();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            log.info("rasp-ssrf-context-hook moudule load finished");
        }
    }

    public static class SSRFContextAdviceListener extends AdviceListener {
        private String className;

        public SSRFContextAdviceListener(String className) {
            this.className = className;
        }

        public void addToConext(Map params) {

            // TODO 添加至上下文

        }

        @Override
        protected void before(Advice advice) throws Throwable {
            // Behavior behavior = advice.getBehavior();
            // log.info("hook in: " + behavior.getName());

            // 对事件打标记
            // TODO 限定条件
            advice.mark("ssrf");

            SSRFContextHolder.Context context = SSRFContextHolder.getContext();
            if (SSRFContextHolder.getContext() == null) {
                context = new SSRFContextHolder.Context();
            }
            context.setAdvices(advice);
            context.setClassNames(this.className);
            SSRFContextHolder.set(context);

            // TODO 格式化上下文
            // addToConext(params);

            ProcessController.noneImmediately();
            super.before(advice);
        }
    }
}
