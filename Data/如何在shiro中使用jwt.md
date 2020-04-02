## 如何在shiro中使用jwt做身份验证

### 一些说明

1. 我的项目使用了shiro做安全管理, shiro默认使用有状态的服务即使用SessionManager这个类管理会话, 但是我想用JWT做安全验证, 这就需要我对shiro做一定程度的自定制.
2. 我先仔细地去shiro官网找了一下相关内容, 但并没有找到如何在shiro中配置jwt. 所以只能自己去读源码, 再根据源码自己找方法在shiro中配置jwt.
3. 假设项目现在还是默认配置, 即使用SessionManager管理会话.
4. **本文详细介绍了如何将默认的shiro配置修改成使用jwt做身份验证, 以及其中原理.**

### 准备工作

1. 过滤器配置如下:

   ```java
   filterMap.put("/sys/login","anon");
   filterMap.put("/**","authc");
   ```

2. 在通过设置断点调试之后, 我找到了shiro的入口类: 

   SpringShiroFilter.

   它是匿名内部类, 在org.apache.shiro.spring.web 包下的ShiroFilterFactoryBean中, 我们发送的每一个请求都会先由它处理.

   ![SpringShiroFilter](SpringShiroFilter.png)

   API文档的描述是:

   >It doesn't matter that the instance is an anonymous inner class here - we're just using it because it is a concrete AbstractShiroFilter instance that accepts injection of the SecurityManager and FilterChainResolver.

   简单说, 我们使用SpringShiroFilter仅仅因为它是一个具体的AbstractShiroFilter 子类, "工具人"罢了, **重点还是在AbstractShiroFilter 类中.**

   那么AbstractShiroFilter 类做了哪些我们需要关注的事呢?

   - 在AbstractShiroFilter中对原生的ServletRequest和ServletResponse做了包装
   - 基于包装后的request和response创建了用于当前请求的subject实例
   - **根据我们在ShiroFilterFactoryBean中的配置和当前访问路径解析出现在要执行的过滤器链**
     - 当前路径是/sys/login, 它是这样配置的: filterMap.put("/sys/login","anon"); 则解析出来的chain变量里面的过滤器是org.apache.shiro.web.filter.authc包下的AnonymousFilter类, 这个类会放行所有的请求.(我们现在就是登录请求)
     - 但如果是/data/label, 它匹配到了这个配置filterMap.put("/**","authc");那么chain变量里面的过滤器就会是org.apache.shiro.web.filter.authc包下的FormAuthenticationFilter类, 这个类需要当前请求被认证过才能放行, 否则直接重定向到我们配置的loginUrl.

3. 下面我们通过debug详细看一下匿名和非匿名请求的处理过程

### 根据Debug看不需要认证的登录url是如何被shiro过滤处理的

1. 先发送登录POST请求到: http://localhost:9000/sys/login, 这个url配置的权限是anon

2. 在org.apache.shiro.web.servlet包下的AbstractShiroFilter类的doFilterInternal处打一个断点, 我们的请求从这里开始被shiro的过滤器处理.

   - 可以看到在第7行和第8行包装了servletRequest和servletResponse
   - 在第10行创建了一个subject
   - 接着进入executeChain方法

   ```java
   protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, final FilterChain chain)
               throws ServletException, IOException {
   
           Throwable t = null;
   
           try {
               final ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
               final ServletResponse response = prepareServletResponse(request, servletResponse, chain);
   
               final Subject subject = createSubject(request, response);
   
               subject.execute(new Callable() {
                   public Object call() throws Exception {
                       updateSessionLastAccessTime(request, response);
                       // 进入这个过滤器
                       executeChain(request, response, chain);
                       return null;
                   }
               });
   ```

3. executeChain这个方法的内容很简单, 第3行会根据当前请求的路径获取当前请求匹配的过滤器链, 第四行就会执行它.

   - 我们现在的请求路径是/sys/login, 它是filterMap.put("/sys/login","anon")这样配置的, chain变量里面的过滤器是org.apache.shiro.web.filter.authc包下的AnonymousFilter类, 这个过滤器会放行所有的请求.

   - 但如果是filterMap.put("/**","authc");那么chain变量里面的过滤器就会是org.apache.shiro.web.filter.authc包下的FormAuthenticationFilter类, 这个过滤器需要当前请求被认证过才能放行, 否则直接重定向到我们配置的loginUrl.

   ```java
   protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
           throws IOException, ServletException {
       FilterChain chain = getExecutionChain(request, response, origChain);
       chain.doFilter(request, response);
   }
   ```

4. 现在进入getExecutionChain这个方法, 先拿到了过滤器链的解析器, 可以看到里面装着shiro默认的所有过滤器和我们配置的过滤器链.

   ![resolver](reslover.png)

5. 在一个循环中, 用当前请求路径和所有我们配置的过滤器链进行匹配, 匹配成功后就返回相应的过滤器链, 详细代码在org.apache.shiro.web.filter.mgt包下的PathMatchingFilterChainResolver类中的FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain)方法, 这里就不多说匹配的过程了.**但注意, 匹配完成后, 返回的过滤器链是被org.apache.shiro.web.servlet包下的ProxiedFilterChain这个类包装过的.这个类对servlet原生的FilterChain做了代理, 会让请求先经过shiro的过滤器链, 再经过tomecat servlet的过滤器链.**

6. 我们回到这里, 在找到了处理当前请求的过滤器链后, doFilter. 注意我们现在是登录请求, 所以拿到的过滤器链里的过滤器是AnonymousFilter. **接下来的现在的请求也全是在AnonymousFilter中处理的.**

   ```java
   protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
           throws IOException, ServletException {
       FilterChain chain = getExecutionChain(request, response, origChain);
       chain.doFilter(request, response);// 现在单步进入这条语句
   }
   ```

7. 现在先看一下AnonymousFilter的继承关系图.

   ![AnonymousFilter](AnonymousFilter.png)

8. 单步调试进入了ProxiedFilterChain类中的doFilter方法, 这个方法调用的就是AnonymousFilter父类OncePerRequestFilter的doFilter方法.  这个类保证了每个请求只会被当前的过滤器处理一次, 包括入口ShiroFilter类.

9. 接着来到AdviceFilter的doFilterInternal方法. AdviceFilter类有什么用呢?

   - 提供了preHandle, postHandle, 和afterCompletion 三个钩子函数

   - 实现了AOP风格的环绕通知
   - **如果运行请求执行, preHandle返回true, 否则返回false**

   ```java
       public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
               throws ServletException, IOException {
   
           Exception exception = null;
   
           try {
               boolean continueChain = preHandle(request, response); //现在进入这里
   
               if (continueChain) {
                   executeChain(request, response, chain);
               }
   
               postHandle(request, response);
   ```

10. 进入preHandle, 来到PathMatchingFilter, 匹配了请求路径和配置为anno的路径

11. 继续单步调试, 接着就来到了终点, AnonymousFilter的onPreHandle方法, 还记得第9条中的preHandle吗, 如果运行当前的请求, 就返回true, 而AnonymousFilter的onPreHandle方法运行所有请求, 所以它永远返回true.

    ```java
    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
        // Always return true since we allow access to anyone
        return true;
    }
    ```

12. 总结一下:

    - 如果想要在shiro中实现jwt认证, 我们需要自己写过滤器处理非匿名请求

    - 从上面的第4点中获取的过滤器链的解析器来看, 我们需要把自己的过滤器提前放进去

      - 查阅了shiro filterFactory的api,  发现了setFilters这个方法, 它可以接受我们自定义的过滤器.

      - 这样配置就可以了

        ```
        filtersMap.put("jwtAuth", new JWTFilter());
        filterFactory.setFilters(filtersMap);
        ```

    - 那么现在的问题就是, 这个过滤器JWTFilter, 需要怎么写? 不如我们先看一下shiro如何处理非匿名请求, 看看它是如何处理的

### 需要认证的登录url是如何被shiro过滤处理的

1. 现在发送一个GET请求到http://localhost:9000/data/label, 一个需要认证才能访问url, 我们在shiro过滤器工厂中配置的是authc

2. 请求还是和之前在AnonymousFilter中的2, 3, 4, 5 ,6一样:

   - 先在AbstractShiroFilter中根据当前请求路径检索出处理当前请求的过滤器FormAuthenticationFilter, 
   - 执行它的odFIlter方法, 依次经过了OncePerRequestFilter(保证当前请求仅被过滤器执行一次), AdviceFilter(实现了AOP风格的环绕通知), PathMatchingFilter(匹配路径)

3. **不过别忘了, 我们上面已经做了登录身份认证, 所以shiro会默认帮我们维持一个会话**

4. 对照看一下FormAuthenticationFilter的继承关系图.

   ![](FormAuthenticationFilter.png)

5. 那么自然而然, PathMatchingFilter下面的四个类, 就是处理身份认证的关键.

6. 查看了他们的实现, 发现关键在于这个方法:

   ```java
   protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
       Subject subject = getSubject(request, response);
       return subject.isAuthenticated();
   }
   ```

7. 原来默认情况下, shiro会在第一次登录认证之后就保存好当前用户的信息到session中, 这样第二次访问就可以很方便的由subject处理了.

### 定制jwt过滤器

1. 接下来我仔细查阅了API文档,  shiro提供了一个过滤器用于无状态服务: NoSessionCreationFilter

   把它加在我们的其它过滤器前面, 就可以禁用session了, 现在我们的过滤器配置是这样的:

   ```java
   filterMap.put("/sys/**","noSessionCreation, anon");
   filterMap.put("/**","noSessionCreation, jwtAuth");
   ```

2. 那么现在问题就只剩下如何实现jwtAuth这个过滤器了.

3. 我的思路是继承AccessControlFilter这个类, 重写其中的isAccessAllowed方法: 

   ```java
   @Override
   protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
           // 从头信息中获取jwt token
           HttpServletRequest httpRequest = (HttpServletRequest) request;
           String token = httpRequest.getHeader("Authorization");
           if (token == null) {
               log.trace("token为空");
               return false;
           }
           Map<String, Object> principal;
           principal = JwtUtils.verifierToken(token);
           if (principal == null) {  // token验证失败, 在onAccessDenied中处理
               return false;
           } else {
               ShiroUtils.setPrincipal(principal);
               // 因为禁用了session, 所以只能自己手动在每次请求通过login方法初始化subject
               initSubject(new JWTUsernamePasswordToken(token));
               return true;
           }
       }
   ```

   这里存在两个问题:

   - 第一个问题是, 因为禁用了session, 所以我们只能自己初始化当前请求的用户信息到subject中. 我查看了默认情况下shiro初始化subject的方法, 发现shiro并没有提供给框架使用者创建subject的方法, 所以只能借助下面的方法来初始化subject

     ```java
     private void initSubject(JWTUsernamePasswordToken token) {
         SecurityUtils.getSubject().login(token);
     }
     ```

     Realm中是这样实现的, 但会在每次非匿名请求时多出一次字符串比对: 

     ```java
     @Override
     protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
         if (authenticationToken instanceof JWTUsernamePasswordToken) {  // 仅用于给非匿名请求初始化subject
             JWTUsernamePasswordToken token = (JWTUsernamePasswordToken)authenticationToken;
             return new SimpleAuthenticationInfo(ShiroUtils.getPrincipal(), token.getCredentials(), this.getName());
         } else {  // 匿名请求走这里
             return new SimpleAuthenticationInfo(ShiroUtils.getPrincipal(), ShiroUtils.getCurUser().getPassword(), this.getName());
         }
     }
     ```

   - 第二个问题是, 因为全局@ExceptionHandler注解无法解析过滤器中的异常, 所以不能直接抛出TokenEncodeException这样的异常来返回给前端信息.

     所以我直接重定向到自定义的url来处理token解码异常
     
     ```java
     @Override
     protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
         // 因为全局@ExceptionHandler注解无法解析过滤器中的异常, 所以不能像下面这样在这里抛出			TokenEncodeException
         // throw new TokenDecodeException("token解析错误");
         // 而是通过重定向到自定义的url再处理错误
         redirectToLogin(request, response);
         return false;
     }
     ```

   完整的过滤器实现代码是这样的:

   ```java
   @Slf4j
   public class JWTFilter extends AccessControlFilter {
       @Override
       protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
           // 从头信息中获取jwt token
           HttpServletRequest httpRequest = (HttpServletRequest) request;
           String token = httpRequest.getHeader("Authorization");
           if (token == null) {
               log.trace("token为空");
               return false;
           }
           Map<String, Object> principal;
           principal = JwtUtils.verifierToken(token);
           if (principal == null) {  // token验证失败, 在onAccessDenied中处理
               return false;
           } else {
               ShiroUtils.setPrincipal(principal);
               // 因为禁用了session, 所以只能自己手动在每次请求通过login方法初始化subject
               initSubject(new JWTUsernamePasswordToken(token));
               return true;
           }
       }
   
       // 借助login初始化subject
       private void initSubject(JWTUsernamePasswordToken token) {
           SecurityUtils.getSubject().login(token);
       }
   
       @Override
       protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
           // 因为全局@ExceptionHandler注解无法解析过滤器中的异常
           // 所以不能像下面这样在这里抛出TokenEncodeException
           // throw new TokenEncodeException("token解析错误");
           // 而是通过重定向到自定义的url再处理错误
           redirectToLogin(request, response);
           return false;
       }
   
       @Override
       protected void postHandle(ServletRequest request, ServletResponse response) throws Exception {
           log.trace("清理了ThreadLocal");
           ShiroUtils.cleanUp();
       }
   }
   ```

### 完结撒花

- 以上的shiro配置思路均为我一人独自整理得出, 所以难免会有错误, 希望大家可以帮我指出我没有发觉的错误~

- 项目已在github上开源, 完整的后端代码在这里:https://github.com/fffffengb/handy-review-notebook-backend
- 参考链接:
  - https://shiro.apache.org
  - https://zhuanlan.zhihu.com/p/74571128