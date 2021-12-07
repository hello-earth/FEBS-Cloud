package cc.mrbird.febs.gateway.common.filter;

import cc.mrbird.febs.gateway.enhance.auth.JwtTokenHelper;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 将登录用户的JWT转化成用户信息的全局过滤器
 * Created by macro on 2020/6/17.
 */
@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private static Logger LOGGER = LoggerFactory.getLogger(AuthGlobalFilter.class);
    private final JwtTokenHelper tokenHelper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (StringUtils.isEmpty(token)) {
            return chain.filter(exchange);
        }
        //从token中解析用户信息并设置到Header中去
        String realToken = token.replace("Bearer ", "");
        String userStr = tokenHelper.getUsernameFromToken(realToken);

        LOGGER.info("AuthGlobalFilter.filter() user:{}",userStr);

        ServerHttpRequest request = exchange.getRequest().mutate().header("user", userStr).build();
        exchange = exchange.mutate().request(request).build();

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}