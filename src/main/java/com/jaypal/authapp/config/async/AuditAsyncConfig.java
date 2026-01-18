package com.jaypal.authapp.config.async;

import com.jaypal.authapp.domain.infrastructure.audit.context.AuditContextHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

@Slf4j
@Configuration
@EnableAsync
public class AuditAsyncConfig {

    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(10_000);
        executor.setThreadNamePrefix("audit-");
        executor.setTaskDecorator(new AuditContextHolder.ContextCopyingDecorator());
        executor.setRejectedExecutionHandler(new AuditRejectionHandler());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();

        log.info("Audit executor initialized - core: 2, max: 4, queue: 10,000");

        return executor;
    }

    private static class AuditRejectionHandler implements RejectedExecutionHandler {
        @Override
        public void rejectedExecution(Runnable task, ThreadPoolExecutor executor) {
            log.error("CRITICAL: Audit task rejected - queue full. Audit log will be lost!");
        }
    }
}

/*
CHANGELOG:
1. Added ContextCopyingDecorator to propagate request context to async threads
2. Added custom RejectionHandler to log when audit queue is full
3. Added graceful shutdown (wait for tasks, 30s timeout)
4. Added logging on initialization
5. This ensures IP and User-Agent are captured in audit logs
*/