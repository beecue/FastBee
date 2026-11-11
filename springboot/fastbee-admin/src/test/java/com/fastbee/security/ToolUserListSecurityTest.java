package com.fastbee.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fastbee.common.core.domain.entity.SysRole;
import com.fastbee.common.core.domain.entity.SysUser;
import com.fastbee.common.core.domain.model.LoginUser;
import com.fastbee.common.core.page.TableDataInfo;
import com.fastbee.common.utils.spring.SpringUtils;
import com.fastbee.data.controller.ToolController;
import com.fastbee.framework.aspectj.DataScopeAspect;
import com.fastbee.framework.web.service.PermissionService;
import com.fastbee.iot.service.impl.ToolServiceImpl;
import com.fastbee.system.mapper.SysUserMapper;
import com.fastbee.system.service.ISysUserService;
import com.fastbee.system.service.impl.SysUserServiceImpl;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ToolUserListSecurityTest {
    private static final String LIST_PERMISSION = "system:user:list";

    @After
    public void clearRequest() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        PageHelper.clearPage();
    }

    @Test
    public void deniesUsersWithoutListPermissionBeforeTheMapperRuns() throws Exception {
        try (Fixture fixture = new Fixture()) {
            login(42L, "iot:device:list");
            assertThrows(AccessDeniedException.class, () -> fixture.controller.list(null, null, null, null, null, null, null));
            verifyNoInteractions(fixture.users);
            assertNull(PageHelper.getLocalPage());
        }
    }

    @Test
    public void nonAdminUsesSystemDataScopeAndCannotSelectAnotherUser() throws Exception {
        try (Fixture fixture = new Fixture()) {
            login(42L, LIST_PERMISSION);
            when(fixture.users.selectUserList(any())).thenAnswer(call -> {
                SysUser query = call.getArgument(0);
                assertEquals(Long.valueOf(42L), query.getUserId());
                assertEquals(Long.valueOf(100L), query.getDeptId());
                assertTrue(query.getParams().get("dataScope").toString().contains("u.user_id = 42"));
                return Collections.emptyList();
            });

            assertEquals(0L, fixture.controller.list(83L, null, "0", null, 999L, null, null).getTotal());
            verify(fixture.users).selectUserList(any());
        }
    }

    @Test
    public void authorizedListingKeepsFiltersAndPaginationButOmitsSensitiveFields() throws Exception {
        try (Fixture fixture = new Fixture()) {
            login(1L, LIST_PERMISSION);
            when(fixture.request.getParameter("pageNum")).thenReturn("2");
            when(fixture.request.getParameter("pageSize")).thenReturn("500");
            SysUser row = new SysUser(83L);
            row.setUserName("sample-user");
            row.setNickName("Sample");
            row.setPhonenumber("13800000000");
            row.setEmail("sample@example.invalid");
            row.setLoginIp("192.0.2.1");
            row.setLoginDate(new Date(0));
            row.setCreateTime(new Date(0));
            row.setDeptId(100L);
            when(fixture.users.selectUserList(any())).thenAnswer(call -> {
                SysUser query = call.getArgument(0);
                assertEquals("sample", query.getUserName());
                assertEquals("0", query.getStatus());
                assertEquals("13800000000", query.getPhonenumber());
                assertEquals(Long.valueOf(100L), query.getDeptId());
                assertEquals("2026-01-01", query.getParams().get("beginTime"));
                assertEquals("2026-01-31", query.getParams().get("endTime"));
                assertEquals("", query.getParams().get("dataScope"));

                Page<SysUser> page = PageHelper.getLocalPage();
                assertEquals(2, page.getPageNum());
                assertEquals(100, page.getPageSize());
                page.setTotal(101);
                page.add(row);
                return page;
            });

            TableDataInfo result = fixture.controller.list(null, "sample", "0", "13800000000", 100L,
                    "2026-01-01", "2026-01-31");
            assertEquals(200, result.getCode());
            assertEquals(101L, result.getTotal());
            assertEquals(1, result.getRows().size());
            JsonNode json = new ObjectMapper().valueToTree(result.getRows().get(0));
            assertEquals(5, json.size());
            assertEquals(83L, json.path("userId").asLong());
            assertEquals("sample-user", json.path("userName").asText());
            assertEquals("Sample", json.path("nickName").asText());
            assertEquals("138****0000", json.path("phonenumber").asText());
            assertTrue(json.path("createTime").isTextual());
            assertNull(PageHelper.getLocalPage());
        }
    }

    private static void login(long id, String permission) {
        SysUser user = new SysUser(id);
        user.setDeptId(100L);
        SysRole role = new SysRole();
        role.setDataScope(DataScopeAspect.DATA_SCOPE_SELF);
        role.setStatus("0");
        role.setPermissions(Collections.singleton(permission));
        user.setRoles(Collections.singletonList(role));
        LoginUser principal = new LoginUser(id, user.getDeptId(), user, Collections.singleton(permission));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList()));
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static class Fixture implements AutoCloseable {
        private final AnnotationConfigApplicationContext context;
        private final Field springBeanFactory;
        private final Object previousBeanFactory;
        private final SysUserMapper users = mock(SysUserMapper.class);
        private final HttpServletRequest request = mock(HttpServletRequest.class);
        private final ToolController controller;

        Fixture() throws Exception {
            Map<String, Object> requestAttributes = new HashMap<>();
            doAnswer(call -> {
                requestAttributes.put(call.getArgument(0), call.getArgument(1));
                return null;
            }).when(request).setAttribute(anyString(), any());
            when(request.getAttribute(anyString())).thenAnswer(call -> requestAttributes.get(call.getArgument(0)));
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            context = new AnnotationConfigApplicationContext(TestConfig.class);
            springBeanFactory = SpringUtils.class.getDeclaredField("beanFactory");
            springBeanFactory.setAccessible(true);
            previousBeanFactory = springBeanFactory.get(null);
            new SpringUtils().postProcessBeanFactory(context.getBeanFactory());

            SysUserServiceImpl userService = new SysUserServiceImpl();
            inject(userService, "userMapper", users);
            ToolServiceImpl toolService = new ToolServiceImpl();
            inject(toolService, "userService",
                    (ISysUserService) context.getBeanFactory().initializeBean(userService, "sysUserService"));
            ToolController target = new ToolController();
            inject(target, "toolService", toolService);
            controller = (ToolController) context.getBeanFactory().initializeBean(target, "toolController");
        }

        @Override
        public void close() throws Exception {
            springBeanFactory.set(null, previousBeanFactory);
            context.close();
        }
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
    @EnableAspectJAutoProxy(proxyTargetClass = true)
    public static class TestConfig {
        @Bean("ss")
        public PermissionService permissionService() {
            return new PermissionService();
        }

        @Bean
        public DataScopeAspect dataScopeAspect() {
            return new DataScopeAspect();
        }

        @Bean
        public StaticMessageSource messageSource() {
            StaticMessageSource source = new StaticMessageSource();
            source.addMessage("query.success", LocaleContextHolder.getLocale(), "Query succeeded");
            return source;
        }
    }
}
