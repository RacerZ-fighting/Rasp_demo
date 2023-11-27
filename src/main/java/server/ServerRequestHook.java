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
import request.HttpRequestContextHolder;
import util.InterfaceProxyUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@MetaInfServices(Module.class)
@Information(id = "rasp-httpServlet-hook")
public class ServerRequestHook implements Module, ModuleLifecycle {
    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    private static final Logger log = LoggerFactory.getLogger(HttpRequestContextHolder.class);

    public void hookRequest() {

        new EventWatchBuilder(moduleEventWatcher)
                .onClass("javax.servlet.http.HttpServlet")
                .includeSubClasses()
                .onBehavior("service")
                .withParameterTypes(
                        "javax.servlet.http.HttpServletRequest",
                        "javax.servlet.http.HttpServletResponse"
                ).onWatch(new AdviceListener() {
                    @Override
                    protected void before(Advice advice) throws Throwable {
                        // 只关心顶层调用
                        if (!advice.isProcessTop()) {
                            return;
                        }
                        log.debug("javax.servlet.http.HttpServlet: set request context");

                        // jvm-sandbox 是在独立的 ClassLoader 中运行的，因此需要做一层代理
                        HttpServletRequest request = InterfaceProxyUtils.puppet(HttpServletRequest.class, advice.getParameterArray()[0]);
                        HttpServletResponse response = InterfaceProxyUtils.puppet(HttpServletResponse.class, advice.getParameterArray()[1]);

                        // 添加请求上下文
                        HttpRequestContextHolder.set(new HttpRequestContextHolder.Context(request, response));
                        super.before(advice);
                    }

                    @Override
                    protected void afterReturning(Advice advice) {
                        // 只关心顶层调用
                        if (!advice.isProcessTop()) {
                            return;
                        }
                        // 移除请求上下文
                        log.debug("javax.servlet.http.HttpServlet: remove request context");
                        HttpRequestContextHolder.remove();
                    }

                });

    }

    @Override
    public void onLoad() throws Throwable {
        log.info(" " +
                "__________    _____     ___________________     __________ .____      ____ ___  _________ \n" +
                "\\______   \\  /  _  \\   /   _____/\\______   \\    \\______   \\|    |    |    |   \\/   _____/ \n" +
                " |       _/ /  /_\\  \\  \\_____  \\  |     ___/     |     ___/|    |    |    |   /\\_____  \\  \n" +
                " |    |   \\/    |    \\ /        \\ |    |         |    |    |    |___ |    |  / /        \\ \n" +
                " |____|_  /\\____|__  //_______  / |____|         |____|    |_______ \\|______/ /_______  / \n" +
                "        \\/         \\/         \\/                                   \\/                 \\/  \n" +
                ":: Rasp Plus ::                                                         (RacerZ)");
    }

    @Override
    public void onUnload() throws Throwable {
        log.info("rasp-httpServlet-hook module unloaded");
    }

    @Override
    public void onActive() throws Throwable {
        log.info("rasp-httpServlet-hook module active");
    }

    @Override
    public void onFrozen() throws Throwable {

    }

    @Override
    public void loadCompleted() {
        if (HookConfig.isEnable("http")) {
            hookRequest();
            log.info("rasp-httpServlet-hook module load finished");
        }
    }

}
