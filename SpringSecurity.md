# Spring Security

# 1:介绍

## 1.1:Spring Security

Spring Security是 Spring 家族中的一个安全管理框架

相比与另外一个安全框架Shiro，它提供了更丰富的功能，社区资源也比Shiro丰富

 Spring Security是一个功能强大且高度可定制的身份验证和访问控制框架

它是用于保护基于Spring的应用程序的实际标准

它提供全面的安全性解决方案，同时在 Web 请求级和方法调用级处理身份确认和授权

Spring Security 充分利用了依赖注入和面向切面编程功能

为应用系统提供声明式的安全访问控制功能

Spring Security是一个框架，致力于为Java应用程序提供身份验证和授权

与所有Spring项目一样，Spring Security的真正强大之处在于可以轻松扩展以满足自定义要求

 在 Java 生态中，目前有 Spring Security 和 Apache Shiro 两个安全框架

Security是一个专注于为Java应用程序提供身份验证和授权的框架

与所有Spring项目一样，Spring Security的真正威力在于它可以多么容易地扩展以满足定制需求

一般Web应用的需要进行认证和授权

 认证（Authentication）：验证当前访问系统的是不是本系统的用户，并且要确认具体是哪个用户

 授权（Authorization）：经过认证后判断当前用户是否有权限进行某个操作

 认证和授权就是SpringSecurity作为安全框架的核心功能


## 1.2:技术选型

### 1:Shiro

首先Shiro较之 Spring Security，Shiro在保持强大功能的同时，还在简单性和灵活性方面拥有巨大优势

Shiro是一个强大而灵活的开源安全框架，主要是以下四大核心

Shiro的四大核心：

1：Authentication：身份认证/登录，验证用户是不是拥有相应的身份

2：Authorization：授权，即权限验证，验证某个已认证的用户是否拥有某个权限

3：Session Manager：会话管理，即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是普通JavaSE环境的，也可以是如Web环境的

4：Cryptography：加密，保护数据的安全性，如密码加密存储到数据库，而不是明文存储

优点：

shiro的代码更易于阅读，且使用更加简单，比较轻便

shiro可以用于非web环境，不跟任何框架或容器绑定，独立运行



缺点：

授权第三方登录需要手动实现

### 2:Spring Security

除了不能脱离Spring，shiro的功能它都有。而且Spring Security对Oauth、OpenID也有支持

Shiro则需要自己手动实现。Spring Security的权限细粒度更高，毕竟Spring Security是Spring家族的

优点：

spring-security对spring整合较好，使用起来更加方便

有更强大的spring社区进行支持

支持第三方的 oauth 授权，官方网站：spring-security-oauth




缺点：

没有Shiro轻量，配置比较重

## 1.3:核心功能

1：认证【Authentication】【你是谁，用户/设备/系统】

2：授权【Authorization】【你能做什么，也叫做权限控制/授权】

## 1.4:实现原理

基于 Filter , Servlet, AOP 实现身份认证和权限验证

# 2:快速入门

## 2.1:基本使用

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
</dependencies>
```

```java
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/first")
    public String first(){
        return "你好";
    }
}
```

启动SpringBoot程序：发现下面存在这样一句话

Using generated security password: d745708a-b124-438f-b38f-f3b3d427a70a

![image-20230331162145685](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230331162145685.png)

用户名默认：user

密码就是上面那个临时密码

登录之后即可访问



## 2.2:原理

![image-20230331162454884](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230331162454884.png)



其实就是AOP拦截了，验证通过之后就可以放行到Controller里面去了



## 2.3:自定义用户名密码

```yml
spring:
  security:
    user:
      name: ZZX
      password: JXLZZX79
```

也就是自定义一个配置文件即可使用



## 2.4:关闭验证

```java
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class,args);
    }
}
```

其实就是关闭自动配置即可，了解SpringBoot自动装配原理就很简单了

# 3:使用内存中的信息

## 3.1:需要配置的类

我们用户的信息来源都来自于 UserDetailsService 里面

当用户登陆的时候，都会去Spring容器里的 UserDetailsService 的逻辑里面去判断

我们自定义 UserDetailsService，就会覆盖默认的 UserDetailsService

我们的 UserDetailsService 有很多的实现

使用内存的数据的话，就使用 InMemoryUserDetailsManager 即可

配置了之后，我们在配置文件配置的内容就失效了

## 3.2:实现

![image-20230418164948195](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418164948195.png)



如果不设置加密器，则会报错：There is no PasswordEncoder mapped for the id "null"

PasswordEncoder 密码映射器为空

Spring Security 5 版本要求密码比较加密，否则报错

我们创建一个PasswordEncoder 即可，这是一个接口【内置多种实现类】

推荐使用的是 BCryptPasswordEncoder

# 4:获取登录的信息

## 4.1:介绍

当用户登录之后，用户的信息会被存储到安全的上下文对象，我们可以获取这个对象来得到用户信息

## 4.2:实现

首先 Authentication 是继承了 Principal 的，所以返回哪个都可以，都是返回身份认证的信息

![image-20230418170252221](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418170252221.png)

![image-20230418170158421](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418170158421.png)

我们随便访问一个接口，就可以返回上面的Json数据，推荐使用第三种方式，可读性高

第三种方式：返回全局安全上下文持有期的全局上下文，再得到认证信息

# 5:配置用户的权限

基于角色 Role 的身份认证， 同一个用户可以有不同的角色

主要存在下面两种方式

1：使用role配置角色

2：使用authorities配置角色

## 5.1:使用role配置角色

![image-20230418171027136](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418171027136.png)

这个时候我们使用 ZZX 登录，再获取一下登录的用户信息，查看一下权限

发现权限存在两个，分别是：ROLE_admin 和 ROLE_normal

发现使用 role 来配置角色，则会自动在 角色 的名称前面加上 ROLE_

## 5.2:使用authorities配置角色

![image-20230418171458540](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418171458540.png)

这个时候我们使用 ZZX 登录，再获取一下登录的用户信息，查看一下权限

发现权限存在两个，分别是：admin 和 normal

发现使用 authorities 来配置角色，则写的是什么，则配置的角色就是什么

## 5.3:发生冲突怎么办

![image-20230418171746270](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418171746270.png)

这个时候，我们使用 ZZX 登录并查看认证信息，发现权限是 ROLE_admin 和 ROLE_normal

我们使用 JXL 来登录并查看认证信息，发现权限是 normal

则得出结论：哪个配置在后面，则就以谁的权限为准

# 6:访问时进行权限确认

## 6.1:介绍

我们需要进行授权之后才可以对资源进行访问，主要就是看当前的登录用户是否具有权限进行访问



授权主要有两种方式

1：针对URL进行授权

2：针对方法进行授权

## 6.2:URL授权

在之前的笔记记录中，登陆的用户可以访问所有资源，不能根据实际情况进行角色管理

要实现授权功能，需重写 WebSecurityConfigureAdapter 中的一个 configure方法

configure 有很多个，我们一般是重写参数是 HttpSecurity 的那个方法



例如下面的配置：意思是user开头的控制器路径下，所有的资源都必须有admin权限才能访问

```java
@Configuration
public class WebSecurityConfig{
    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurerAdapter(){
        return new WebSecurityConfigurerAdapter() {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // 开启http请求的授权
                http.authorizeRequests()
                        // 访问/user/** 这样的url，必须有admin权限
                        .mvcMatchers("/user/**").hasRole("admin")
                    	// 任何请求均需要认证
                        .anyRequest().authenticated();
                
                // 放行登录的表单请求
                http.formLogin().permitAll();
            }
        };
    }
}
```

配置：无论是admin角色，还是normal角色都可以访问 user/select

```java
http.authorizeRequests()
    .mvcMatchers("/user/select")
    .hasAnyRole("admin","normal")
    .anyRequest().authenticated();
```

除了含有 hasRole 方法之外，还有一个 hasAuthority 和 hasAnyAuthority

区别我们在之前已经说过了，这里也是一样类似的

## 6.3:方法授权

上面学习的认证与授权都是基于URL的，我们也可以通过注解灵活的配置方法安全

我们先通过 @EnableGlobalMethodSecurity(prePostEnabled = true) 开启基于注解的安全配置

在方法上加@PostAuthorize注解

@PreAuthorize 在方法执行前进行验证，@PostAuthorize 在方法执行后进行验证

在实际上的使用中，我们只使用 @PreAuthorize ，除非有特殊需求

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class,args);
    }
}
```

```java
@PreAuthorize(value = "hasRole('admin')")
@GetMapping("/select")
public String select(){
    return "查询操作";
}
@PreAuthorize(value = "hasAnyRole('admin','normal')")
@PostMapping("/insert")
public String insert(){
    return "插入操作";
}
```

上面不止可以填 hasRole，还有 hasAnyRole，hasAuthority，hasAnyAuthority【区别和之前一样】

![image-20230418192040626](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418192040626.png)

这个时候使用 ZZX 登录，发现访问 /user/select 和 /user/insert 都没问题

使用 JXL 登录，发现访问 /user/select 没权限，访问 /user/insert 可以

# 7:几个处理器

## 7.1:介绍

现在都是前后端分离，我们一般都是进行处理，返回JSON数据给前端，至于页面的跳转，留给前端进行处理

安全框架为我们提供了几个处理器

1：认证成功的处理器

2：认证失败的处理器

3：退出成功的处理器

4：访问拒绝的处理器【也就是登录成功，但是访问方法没有权限的处理器】

## 7.2:认证成功

认证成功之后，就会执行这个接口 AuthenticationSuccessHandler，默认就是不做处理放行了

我们在前端登录之后，后台进行认证处理，我们应该返回一个JSON数据

我们只需要在 Spring 容器里面注入这个对象，当认证成功了自己就会进行处理了

![image-20230418201806882](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418201806882.png)

配置 WebSecurityConfigurerAdapter 类

![image-20230418195320010](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418195320010.png)

这个时候我们进行认证【也就是登录】发现登录成功之后返回了JSON字符串给前端，这样便于前端进行处理跳转



## 7.3:认证失败

认证失败的逻辑和这个就一样了，使用的是 AuthenticationFailureHandler 这个类

![image-20230418195808576](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418195808576.png)

配置 WebSecurityConfigurerAdapter 类

![image-20230418195640735](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418195640735.png)

这个时候进行登录，登录失败，则直接返回上面错误的 JSON 信息了，正确则返回正确的 JSON 信息



## 7.4:一个不错的实践

```java
@Bean
public AuthenticationFailureHandler failureHandler() {
    return new AuthenticationFailureHandler() {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request,
                                            HttpServletResponse response,
                                            AuthenticationException exception)
                throws IOException, ServletException {
            // 返回JSON出去【假定400就是登录失败的错误码】
            HttpResult result= new HttpResult(400);
            if(exception instanceof BadCredentialsException){
                result.setMessage("密码不正确");
            }else if(exception instanceof DisabledException){
                result.setMessage("账号被禁用");
            }else if(exception instanceof UsernameNotFoundException){
                result.setMessage("用户名不存在");
            }else if(exception instanceof CredentialsExpiredException){
                result.setMessage("密码已过期");
            }else if(exception instanceof AccountExpiredException){
                result.setMessage("账号已过期");
            }else if(exception instanceof LockedException){
                result.setMessage("账号被锁定");
            }else{
                result.setMessage("未知异常");
            }
            // 把result转成JSON
            String json = objectMapper.writeValueAsString(result);
            // 返回JSON字符串
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter writer = response.getWriter();
            writer.println(json);
            writer.flush();;
        }
    };
}
```

失败了这个方法，有一个Exception对象，我们可以根据这个异常对象，返回更加精确的原因

一般就是定义我们统一返回的HttpResult对象，根据异常情况分类对里面的 message 字段进行赋值



## 7.5:退出成功

![image-20230418203218639](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418203218639.png)

配置 WebSecurityConfigurerAdapter 类

![image-20230418203322735](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418203322735.png)



## 7.6:访问拒绝

也就是默认返回的 403 的处理器

![image-20230418203343155](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418203343155.png)

配置 WebSecurityConfigurerAdapter 类

![image-20230418212143056](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418212143056.png)

# 8:自定义用户信息

## 8.1:介绍

我们之前使用的用户信息，也就是 UserDetailsService，都是使用 InMemoryUserDetailsManager 来创建的

用户的信息实际上是封装在 UserDetails 里面的

我们在实际项目开发里，都是使用自己的数据库里面的信息

也就是我们要自己定义 UserDetails，里面自己来设置具体的内容

UserDetailsService：处理用户数据的服务

UserDetails：真正的用户数据

## 8.2:基本使用

我们建立自己的 UserDetails，数据我先全部写死，用户ZZX，密码JXLZZX79

权限 admin 和 normal，其余的验证字段全部为真

```java
public class MyUserDetails implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority>list=new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_admin"));
        list.add(new SimpleGrantedAuthority("ROLE_normal"));
        return list;
    }

    @Override
    public String getPassword() {
        return "$2a$10$YNjuY26U0.Pe/kQBqBVii.WiymaQPSUFurLx/VRIr0qmiqrQ5qE1y";
    }

    @Override
    public String getUsername() {
        return "ZZX";
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

配置 UserDetailsService

![image-20230418215105435](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230418215105435.png)

验证成功之后返回我们自己的 UserDetails 对象

这个时候使用 ZZX 和 JXLZZX79 登录之后，访问 /user/select 成功

# 9:基于数据库的认证

## 9.1:介绍

其实和上面自定义用户信息是十分类似的，只不过我们使用的是数据库的信息来构建用户信息

## 9.2:建表

这里建立的表是符合RBAC权限模型的表

1：用户表【userId】

2：角色表【roleId】

3：菜单表【menuId】

4：用户角色表【userId，roleId】

5：角色菜单表【roleId，menuId】



我们拿到一个用户的ID，怎么去查询能操作哪些资源呢？

1：根据用户的ID关联查询用户角色表【可以查到对应用户的角色ID】

2：根据查询到的角色ID去关联查询角色菜单表【可以查询到对应的菜单ID】

3：根据菜单ID去查询菜单表，就可以拿到对应能操作的资源，也就是权限了



**用户表：sys_user**

![image-20230419105111478](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419105111478.png)

****

**角色表：sys_role**

![image-20230419105157807](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419105157807.png)

****

**用户角色表：sys_user_role**

![image-20230419105231135](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419105231135.png)

****

**菜单表：sys_menu**

![image-20230419105318600](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419105318600.png)

****

**角色菜单表：sys_role_menu**

![image-20230419105354725](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419105354725.png)

****

```sql
# 查询用户ID为1的权限信息

# 根据用户ID去查询用户角色表，得到角色的所有角色的ID信息

select rid from sys_role_user where uid = 1

# 根据得到的角色ID去查询菜单角色表，得到所有菜单的ID信息

select mid from sys_role_menu where rid in (select rid from sys_role_user where uid = 1)

# 根据得到的菜单ID去查询菜单到底有什么权限

select code from sys_menu where id in (
		select mid from sys_role_menu where rid in (
				select rid from sys_role_user where uid = 1
		)
)
```

**关联查询的写法：**

```sql
# 关联查询
select distinct menu.code
	from sys_user user 
	# 关联查询role_user，得到用户的角色ID
	join sys_role_user role_user on user.id=role_user.uid
	# 关联查询role_menu，得到用户对应的角色ID的所有菜单ID
	join sys_role_menu role_menu on role_menu.rid=role_user.rid
	# 关联查询菜单表，得到用户对应的角色ID的所有菜单ID对应的菜单信息
	join sys_menu menu on menu.id=role_menu.mid
	where user.id = 1
```

****

## 9.3:实践步骤

### 1:新建实体类

```java
@Data
public class SysUser implements Serializable {
    private static final long serialVersionUID = 898763687469145823L;
    // 用户ID
    private Integer id;
    // 用户名
    private String username;
    // 密码
    private String password;
    // 性别
    private String sex;
    // 地址
    private String address;
    // 是否启用
    private Integer enabled;
    // 是否未过期
    private Integer accountNoExpired;
    // 凭证是否无错误
    private Integer credentialsNoExpired;
    // 账户是否未锁定
    private Integer accountNoLocked;
}
```

有的喜欢把实体类直接实现 UserDetails

我这里没有实现 UserDetails，为了结构清晰，我自己新建立一个类

### 2:Mapper

```java
public interface SysUserMapper extends BaseMapper<SysUser> {
    /**
     * 根据用户名查找用户
     * @param username
     * @return
     */
    SysUser queryByUsername(String username);
}
```

![image-20230419114209195](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419114209195.png)

****

```java
public interface SysRoleMapper extends BaseMapper<SysRole> {
    /**
     * 根据用户ID查询角色信息
     * @param userId
     * @return
     */
    List<String>queryRolesByUserId(Integer userId);
}
```

![image-20230419114232526](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419114232526.png)

****

```java
public interface SysMenuMapper extends BaseMapper<SysMenu> {
    /**
     * 根据用户ID查询更细粒度的权限，精确到方法级别
     * @param userId
     * @return
     */
    List<String> queryPermissionByUserId(Integer userId);
}
```

![image-20230419114250330](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419114250330.png)

上面分别是得到角色的字符串描述信息，还有一个是得到具体的每一个细化的权限的字符串信息



### 3:配置UserDetails

没有在实体类直接实现 UserDetails 类，而是新建的一个类，我们把用户对象作为参数传递，更加清晰

```java
@Data
public class SysUserDetails implements UserDetails {

    // 用户实体类
    private SysUser sysUser;

    // 权限集合
    private List<GrantedAuthority> authorityList;

    public SysUserDetails() {
    }

    public SysUserDetails(SysUser sysUser) {
        this.sysUser = SysUserDetails.this.sysUser;
    }

    public SysUserDetails(SysUser sysUser, List<GrantedAuthority> authorityList) {
        this.sysUser = sysUser;
        this.authorityList = authorityList;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorityList;
    }

    @Override
    public String getPassword() {
        return sysUser.getPassword();
    }

    @Override
    public String getUsername() {
        return sysUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return sysUser.getAccountNoExpired() == 1;
    }

    @Override
    public boolean isAccountNonLocked() {
        return sysUser.getAccountNoLocked() == 1;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return sysUser.getCredentialsNoExpired() == 1;
    }

    @Override
    public boolean isEnabled() {
        return sysUser.getEnabled() == 1;
    }
}
```



### 4:配置SysUserDetailsService

注意：我这里把方法配置的细粒度的，类似这种 @PreAuthorize(value = "hasRole('student:query')")

所以我使用的是 sysMenuMapper 来查询细粒度的权限



如果我这里配置的方法是 @PreAuthorize(value = "hasRole('admin')")

则我这里就可以使用 sysRoleMapper 来查询权限了，具体看自己怎么设计

```java
@Configuration
public class SysUserDetailsService {

    @Autowired
    private SysUserMapper sysUserMapper;

    @Autowired
    private SysMenuMapper sysMenuMapper;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String usernamr) 
                throws UsernameNotFoundException {
                // 查询数据库找到对应的用户
                SysUser sysUser = sysUserMapper.queryByUsername(usernamr);
                if (sysUser == null) {
                    throw new UsernameNotFoundException("用户名不存在");
                }
                // 找到用户ID
                Integer userId = sysUser.getId();
                // 根据用户ID去连表查询用户角色集合
                List<String> list = sysMenuMapper.queryPermissionByUserId(userId);
                List<GrantedAuthority> roles = new ArrayList<>();
                // 封装到角色集合
                list.forEach((role) -> {
                    roles.add(new SimpleGrantedAuthority(role));
                });
                // 封装SecurityUser对象
                SysUserDetails sysUserDetails = new SysUserDetails();
                sysUserDetails.setSysUser(sysUser);
                System.out.println(sysUserDetails.isCredentialsNonExpired());
                sysUserDetails.setAuthorityList(roles);
                return sysUserDetails;
            }
        };
    }
}
```

主要思路就是：根据用户名查询用户，再得到用户的ID，再根据用户的ID去查询权限



我们登录之后访问一下用户的信息，可以得到下面的结果

![image-20230419143751212](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230419143751212.png)

这个时候就可以访问我们的方法了，对于几个处理器的编写我这里就没写了

如认证成功的处理器，认证失败的处理器，退出成功的处理器，认证成功但是权限不足的处理器



### 5:流程

也就是前端发起请求，填写账户密码

这个时候会被 WebSecurityConfigurerAdapter 的配置拦截

1：我们配置的 WebSecurityConfigurerAdapter 使用了 PasswordEncoder 

PasswordEncoder 采用的是 BCryptPasswordEncoder 

则会先把用户填写的密码用 BCryptPasswordEncoder 进行加密



2：我们 Spring 容器里配置了 UserDetailsService 则会进入 UserDetailsService 的处理逻辑

在 UserDetailsService 里面重写了方法 loadUserByUsername( name )

我们重写的逻辑是根据这个参数去查数据库得到用户 SysUser

再根据用户去得到用户ID，拿着用户ID去关联查询得到用户的权限

我们把数据封装在了自己定义的 UserDetails 对象里面

这个时候就会去验证在 WebSecurityConfigurerAdapter 拦截处的账号密码

和自定义 UserDetails  对象里面封装的账号密码是不是一致的

另外我们使用 @EnableGlobalMethodSecurity(prePostEnabled = true)开启了方法级别的权限控制

这样就可以查看当前User对象里面的用户的权限是不是满足

## 9.4:常用注解

几个重要的类或者注解

1：WebSecurityConfigurerAdapter

2：PasswordEncoder

3：@EnableGlobalMethodSecurity(prePostEnabled = true)

4：@PreAuthorize(value = "hasAnyRole('admin','normal')")

5：UserDetailsService

6：UserDetails

7：GrantedAuthority

8：SimpleGrantedAuthority(String role)

## 9.5:小结

我们一般使用的就是这种RBAC的权限模型，五张表

自定义 UserDetails 和 UserDetailsService

然后在 UserDetailsService 里面进行业务逻辑的处理

UserDetailsService 只有一个方法，就是 loadUserByUsername

我们一般就是根据这个先查询用户，把这个用户封装到我们自定义的 UserDetails

有的喜欢把实体类直接实现 UserDetails【也可以，但是不推荐】

然后查询到用户之后，我们再查询角色，权限信息再封装到  UserDetails 里面

最后返回我们自定义的 UserDetails 即可

还要配置几个处理器

1：认证成功的处理器

2：认证失败的处理器

3：退出成功的处理器

4：认证成功但访问缺乏权限的处理器



还要配置 WebSecurityConfigurerAdapter，重写 configure(HttpSecurity http) 方法

在这里可以配置让所有的请求进行认证授权，配置URL授权，并且配置上面几个处理器

最后还可以开启方法级别的注解，配置方法执行需要的权限



# 10:JWT

## 10.1:Base64介绍

所谓Base64，就是说选出64个字符：小写字母a-z、大写字母A-Z、数字0-9、符号"+"、"/"

再加上作为垫字的"="，实际上是使用65个字符作为一个基本字符集

然后，其他所有符号都转换成这个字符集中的字符

如果有人给了你一串字符，里面有 @ 之类的，那么就是忽悠你



任何文件都可以进行 Base64 编码

我们直接使用记事本打开视频，乱码

直接先进行 base64 编码，再打开，不乱码了，就是一串字符

## 10.2:Base64原理

把文件的每三个字节变为四个字节，则文件变为 Base64 编码之后会变大，好处就是可见，不会乱码

## 10.3:Base64Url

Base64Url是一种在Base64的基础上编码形成新的编码方式，为了编码能在网络中安全顺畅传输

需要对传输的数据进行 Base64 的编码



JWT 只通过算法实现对Token合法性的验证，不依赖数据库，Memcached的等存储系统

因此可以做到跨服务器验证，只要密钥和算法相同，不同服务器程序生成的Token可以互相验证

## 10.4:什么是JWT

官网：https://jwt.io/

JWT是JSON Web Token的缩写，即JSON Web令牌，是一种自包含令牌

![image-20230205093809709](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230205093809709.png)

**JWT的作用：**
JWT 最重要的作用就是对 token信息的防伪作用，主要就是对客户端传来的令牌进行验证是否合法



**JWT的原理：**
一个JWT由三个部分组成：

- JWT头
- 有效载荷
- 签名哈希

由这三个部分组合，中间使用`.`来分割，最后由这三者组合进行 base64 编码得到JWT

## 10.5:JWT的组成

官网给的组成示例如下：

![image-20230205094254689](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230205094254689.png)

### 1:JWT头

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

在上面的代码中，alg属性表示签名使用的算法，默认为HMAC SHA256（写为HS256）

typ 属性表示令牌的类型，JWT令牌统一写为JWT

最后，使用`Base64 URL算法`将上述JSON对象转换为字符串保存



参数一：加密算法，有很多种，可选

参数二：令牌类型，这个就是JWT



### 2:有效载荷

有效载荷部分，是JWT的主体内容部分，也是一个JSON对象，包含需要传递的数据

JWT指定七个字段供选择【都是可选字段】

```elixir
iss: jwt签发者
sub: 主题
aud: 接收jwt的一方
exp: jwt的过期时间，这个过期时间必须要大于签发时间
nbf: 定义在什么时间之前，该jwt都是不可用的
iat: jwt的签发时间
jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
```

除以上默认字段外，我们还可以自定义私有字段，如下例：

```json
{
  "name": "ZZX",
  "admin": true,
  "avatar": "ZZX.jpg"
}
```

官网的示例：

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

注意：默认情况下JWT是未加密的，任何人都可以解读其内容，也就是默认请况下，任何人拿到那段紫色的内容都可以还原出原始的Json对象，只需要使用Base64 URL算法解码就可以了，因此不要构建隐私信息字段，存放保密信息，以防止信息泄露

### 3:签名哈希

签名哈希部分是对上面两部分数据签名，通过指定的算法生成哈希，以确保数据不会被篡改首先，需要指定一个密码(secret)，可以自定义，该密码仅仅为保存在服务器中，并且不能向用户公开。然后，使用JWT头中指定的签名算法（默认情况下为HMAC SHA256）根据以下公式生成签名

```
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(claims), secret)
```

![image-20230205094254689](https://zzx-note.oss-cn-beijing.aliyuncs.com/springsecurity/image-20230205094254689.png)

base64UrlEncode(header)：把JWT头进行base64Url编码，得到粉红色信息

base64UrlEncode(claims)：把有效载荷进行base64Url编码，得到紫色信息

HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(claims), secret)

使用HMACSHA256算法得到签名哈希，需要一个密码的参与【可自定义】，得到签名哈希



在计算出签名哈希后，JWT头，有效载荷和签名哈希的三个部分组合成一个字符串

每个部分用"."分隔，就构成整个JWT对象

## 10.6:JWT的用法

客户端接收服务器返回的JWT，将其存储在Cookie或localStorage中

此后，客户端将在与服务器交互中都会带JWT【不像Cookie，需要前端编码实现】

如果将它存储在Cookie中，就可以自动发送，但是不会跨域【也就是跨域名了之后，Cookie就不会自动发送了】

所以我们处理的话一般是将它放入HTTP请求的Header 的Authorization字段中【推荐】

也可以将JWT放置于POST请求的数据主体中

## 10.7:JWT问题和趋势

1、JWT默认不加密，但可以加密。生成原始令牌后，可以使用该令牌再次对其进行加密

2、当JWT未加密时，一些私密数据不推荐通过JWT传输，因为Base64URL可以直接解码

3、JWT不仅可用于认证，还可用于信息交换。用JWT有助于减少服务器请求数据库的次数

4、JWT的最大缺点是服务器不保存会话状态【因为JWT存在于客户端】所以在使用期间不可能取消令牌或更改令牌的权限，也就是说，一旦JWT签发，在有效期内将会一直有效

5、JWT本身包含认证信息，因此一旦信息泄露，任何人都可以获得令牌的所有权限。为了减少盗用，JWT的有效期不宜设置太长。对于某些重要操作，用户在使用时应该每次都进行身份验证

6、为了减少盗用和窃取，JWT不建议使用HTTP协议来传输代码，而是使用加密的HTTPS加密传输协议进行传输【代码没有区别】

## 10.8:JWT工具类

```java
public class JwtUtil {

    // 过期时间 15分钟
    private static final long EXPIRE_TIME = 15 * 60 * 1000;

    // 私钥
    private static final String TOKEN_SECRET = "ZZXLOVEJXL";

    /**
     * 构建Token，有效期为15分钟
     * 参数集合是参与构建Token的有效载荷部分
     * 构建成功返回字符串，构建失败返回null
     * @param map
     * @return
     */
    public static String token(Map<String, Object> map) {
        try {
            // 设置过期时间
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);

            // 私钥和加密算法
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);

            // 设置头部信息
            Map<String, Object> header = new HashMap<>(2);
            header.put("typ", "jwt");
            header.put("alg", "HS256");

            // 准备构建Token字符串
            JWTCreator.Builder builder = JWT.create()
                    .withSubject("JWT") // 主题
                    .withHeader(header) // header信息
                    .withIssuedAt(new Date()) //颁发时间
                    .withExpiresAt(date); //过期时间

            // 构建Token的有效载荷部分
            map.entrySet().forEach(entry -> {
                if (entry.getValue() instanceof Integer) {
                    builder.withClaim( entry.getKey(),(Integer)entry.getValue());
                } else if (entry.getValue() instanceof Long) {
                    builder.withClaim( entry.getKey(),(Long)entry.getValue());
                } else if (entry.getValue() instanceof Boolean) {
                    builder.withClaim( entry.getKey(),(Boolean) entry.getValue());
                } else if (entry.getValue() instanceof String) {
                    builder.withClaim( entry.getKey(),String.valueOf(entry.getValue()));
                } else if (entry.getValue() instanceof Double) {
                    builder.withClaim( entry.getKey(),(Double)entry.getValue());
                } else if (entry.getValue() instanceof Date) {
                    builder.withClaim( entry.getKey(),(Date)entry.getValue());
                }
            });

            // 返回构建的Token字符串
            return builder.sign(algorithm);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 验证Token的正确性
     * 成功返回true，失败返回false
     * @param token
     * @return
     */
    public static boolean verify(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 获取用户传入的有效载荷信息
     * 获取成功返回Map集合，获取失败返回null
     * @param token
     * @return
     */
    public static Map<String, Claim> getClaims(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            Map<String, Claim> result = verifier.verify(token).getClaims();
            return result;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 获取Token过期时间
     * 获取成功返回Date对象，失败返回null
     * @param token
     * @return
     */
    public static Date getExpiresAt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            return JWT.require(algorithm).build().verify(token).getExpiresAt();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 获取Token发布时间
     * 获取成功返回Date对象，失败返回null
     * @param token
     * @return
     */
    public static Date getIssuedAt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            return JWT.require(algorithm).build().verify(token).getIssuedAt();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证Token是否失效
     * 失效返回true，未失效返回false
     * @param token
     * @return
     */
    public static boolean isExpired(String token) {
        try {
            final Date expiration = getExpiresAt(token);
            return expiration.before(new Date());
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            return true;
        }
    }
    
    /**
     * 直接Base64解密获取header内容
     * 返回header的字符串表示
     * @param token
     * @return
     */
    public static String getHeaderByBase64(String token) {
        if (StringUtils.isEmpty(token)) {
            return null;
        } else {
            byte[] header_byte = Base64.getDecoder().decode(token.split("\\.")[0]);
            String header = new String(header_byte);
            return header;
        }
    }

    /**
     * 直接Base64解密获取payload内容
     * 返回有效载荷的字符串表示
     * @param token
     * @return
     */
    public static String getPayloadByBase64(String token) {
        if (StringUtils.isEmpty(token)) {
            return null;
        } else {
            byte[] payload_byte = Base64.getDecoder().decode(token.split("\\.")[1]);
            String payload = new String(payload_byte);
            return payload;
        }
    }
}
```

## 10.9:解决无法退出问题

问题：因为JWT无状态，如果要实现退出功能无法实现

因为用户即时点击了退出，但是只要 JWT 没有过期，下次访问资源还是有效的

这个时候用户直接点击其他的页面，还是不需要提示登录

但是用户主动点击了退出，目的就是下次访问资源需要登录

正是因为 JWT 的无状态导致无法了退出的问题



怎么解决？

使用 Redis 把 JWT 存入 Redis

当用户登录成功，返回Token，存入 Redis，存入用户浏览器的本地存储

用户访问的时候，前端会写代码携带 Token 到 Header



用户主动点击退出的逻辑：

把 Redis 里面的这个 JWT 删除了



用户访问资源的时候，业务流程是这样的：

1：先查询 JWT 是不是有效的，如果无效，则肯定提示重新登录了

2：JWT 有效，则查询 Redis 是不是存在 JWT，存在则表明用户没有主动点击过退出

3：JWT 有效，但是查询 Redis 不存在 JWT，表明用户主动点击过退出，这个时候编码提示重新登录

# 11:最佳实践

下面的实践是根据 RBAC 模型来实现的

## 11.1:定义返回对象

```java
@Data
public class HttpResult {
    private Boolean success;
    private Integer code;
    private String message;
    private Map<String, Object> data = new HashMap<>();

    /**
     * 成功，缺乏数据
     *
     * @return
     */
    public static HttpResult ok() {
        HttpResult httpResult = new HttpResult();
        httpResult.setSuccess(HttpResultEnum.SUCCESS.getSuccess());
        httpResult.setCode(HttpResultEnum.SUCCESS.getCode());
        httpResult.setMessage(HttpResultEnum.SUCCESS.getMessage());
        return httpResult;
    }

    /**
     * 失败，缺乏数据
     *
     * @return
     */
    public static HttpResult error() {
        HttpResult httpResult = new HttpResult();
        httpResult.setSuccess(HttpResultEnum.FAIL.getSuccess());
        httpResult.setCode(HttpResultEnum.FAIL.getCode());
        httpResult.setMessage(HttpResultEnum.FAIL.getMessage());
        return httpResult;
    }

    /**
     * 设置泛型，缺乏数据
     *
     * @param httpResultEnum
     * @return
     */
    public static HttpResult setResult(HttpResultEnum httpResultEnum) {
        HttpResult httpResult = new HttpResult();
        httpResult.setSuccess(httpResultEnum.getSuccess());
        httpResult.setCode(httpResultEnum.getCode());
        httpResult.setMessage(httpResultEnum.getMessage());
        return httpResult;
    }

    /**
     * 添加单个键值对数据
     *
     * @param key
     * @param value
     * @return
     */
    public HttpResult data(String key, Object value) {
        this.data.put(key, value);
        return this;
    }
}
```

## 11.2:定义返回的泛型

```java
public enum ResultEnum {
    SUCCESS(true,200,"成功"),
    FALSE(true,2000,"成功");

    private Boolean success;
    private Integer code;
    private String message;

    ResultEnum(java.lang.Boolean success, Integer code, String message) {
        this.success = success;
        this.code = code;
        this.message = message;
    }
}
```

后续有业务的需求，则直接在上面添加泛型即可

## 11.3:三个实体类

定义用户实体类

```java
@Data
public class SysUser implements Serializable {
    private static final long serialVersionUID = 898763687469145823L;
    // 用户ID
    private Integer id;
    // 用户名
    private String username;
    // 密码
    private String password;
    // 性别
    private String sex;
    // 地址
    private String address;
    // 是否启用
    private Integer enabled;
    // 是否未过期
    private Integer accountNoExpired;
    // 凭证是否无错误
    private Integer credentialsNoExpired;
    // 账户是否未锁定
    private Integer accountNoLocked;
}
```

定义角色实体类

```java
@Data
public class SysRole implements Serializable {
    private static final long serialVersionUID = 8598773336249188190L;
    private Integer id;
    private String rolename;
    private String remark;
}
```

定义能执行的菜单列表实体

```java
@Data
public class SysMenu implements Serializable {
    private static final long serialVersionUID = -3598126038428785070L;
    private Integer id;
    private Integer pid;
    private Integer type;
    private String name;
    private String code;
}
```

## 11.4:数据库操作

```java
public interface SysUserMapper extends BaseMapper<SysUser> {
    /**
     * 根据用户名查找用户
     * @param username
     * @return
     */
    SysUser queryByUsername(String username);
}
```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.zzx.user.mapper.SysUserMapper">

    <!-- 根据用户名查找用户 -->
    <select id="queryByUsername" resultType="com.zzx.user.entity.SysUser">
        select *
        from sys_user
        where username = #{username}
    </select>
</mapper>
```

****

```java
public interface SysRoleMapper extends BaseMapper<SysRole> {
    /**
     * 根据用户ID查询角色信息
     * @param userId
     * @return
     */
    List<String>queryRolesByUserId(Integer userId);
}
```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.zzx.user.mapper.SysRoleMapper">

    <!-- 根据用户ID联表查询用户的角色字符串列表 -->
    <select id="queryRolesByUserId" resultType="java.lang.String">
        select distinct role.rolename
        from sys_user user
	        join sys_role_user role_user on user.id=role_user.uid
            join sys_role role on role.id = role_user.rid
        where user.id = #{userId}
    </select>
</mapper>
```

****

```java
public interface SysMenuMapper extends BaseMapper<SysMenu> {
    /**
     * 根据用户ID查询更细粒度的权限，精确到方法级别
     * @param userId
     * @return
     */
    List<String> queryPermissionByUserId(Integer userId);
}
```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.zzx.user.mapper.SysMenuMapper">

    <!-- 根据用户ID联表查询用户的操作菜单列表 -->
    <select id="queryPermissionByUserId" resultType="java.lang.String">
        select distinct menu.code
        from sys_user user
	        join sys_role_user role_user on user.id=role_user.uid
            join sys_role_menu role_menu on role_menu.rid=role_user.rid
            join sys_menu menu on menu.id=role_menu.mid
        where user.id = #{userId}
    </select>
</mapper>
```

## 11.5:UserDetails

```java
@Data
public class SysUserDetails implements UserDetails {

    // 用户实体类
    private SysUser sysUser;

    // 权限集合
    private List<GrantedAuthority> authorityList;

    public SysUserDetails() {
    }

    public SysUserDetails(SysUser sysUser) {
        this.sysUser = SysUserDetails.this.sysUser;
    }

    public SysUserDetails(SysUser sysUser, List<GrantedAuthority> authorityList) {
        this.sysUser = sysUser;
        this.authorityList = authorityList;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorityList;
    }

    @Override
    public String getPassword() {
        return sysUser.getPassword();
    }

    @Override
    public String getUsername() {
        return sysUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return sysUser.getAccountNoExpired() == 1;
    }

    @Override
    public boolean isAccountNonLocked() {
        return sysUser.getAccountNoLocked() == 1;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return sysUser.getCredentialsNoExpired() == 1;
    }

    @Override
    public boolean isEnabled() {
        return sysUser.getEnabled() == 1;
    }
}
```

## 11.6:UserDetailsService

```java
@Configuration
public class SysUserDetailsService {

    @Autowired
    private SysUserMapper sysUserMapper;

    @Autowired
    private SysMenuMapper sysMenuMapper;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String usernamr) 
                throws UsernameNotFoundException {
                // 查询数据库找到对应的用户
                SysUser sysUser = sysUserMapper.queryByUsername(usernamr);
                if (sysUser == null) {
                    throw new UsernameNotFoundException("用户名不存在");
                }
                // 找到用户ID
                Integer userId = sysUser.getId();
                // 根据用户ID去连表查询用户角色集合
                List<String> list = sysMenuMapper.queryPermissionByUserId(userId);
                List<GrantedAuthority> roles = new ArrayList<>();
                // 封装到角色集合
                list.forEach((role) -> {
                    roles.add(new SimpleGrantedAuthority(role));
                });
                // 封装SecurityUser对象
                SysUserDetails sysUserDetails = new SysUserDetails();
                sysUserDetails.setSysUser(sysUser);
                System.out.println(sysUserDetails.isCredentialsNonExpired());
                sysUserDetails.setAuthorityList(roles);
                return sysUserDetails;
            }
        };
    }
}
```

如果我们配置的那些方法的权限都是针对角色的，则我们直接使用 SysRoleMapper 即可

如果我们配置的那些方法的权限都是针对具体方法的，细粒度的，则我们直接使用 sysMenuMapper 即可



## 11.7:几个处理器

```java
@Configuration
public class AuthenticationHandlerConfig {

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * 认证成功的处理器
     * @return
     */
    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication)
                    throws IOException, ServletException {
                // 封装结果对象
                HttpResult result = HttpResult.ok().data("item", "认证成功");
                String json = objectMapper.writeValueAsString(result);
                response.setContentType("application/json;charset=UTF-8");
                PrintWriter writer = response.getWriter();
                writer.println(json);
                writer.flush();
            }
        };
    }

    /**
     * 认证失败的处理器
     * @return
     */
    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request,
                                                HttpServletResponse response,
                                                AuthenticationException exception)
                    throws IOException, ServletException {

                // 封装结果对象
                HttpResult result = HttpResult.ok();
                if(exception instanceof BadCredentialsException){
                    result.setMessage("密码不正确");
                }else if(exception instanceof DisabledException){
                    result.setMessage("账号被禁用");
                }else if(exception instanceof UsernameNotFoundException){
                    result.setMessage("用户名不存在");
                }else if(exception instanceof CredentialsExpiredException){
                    result.setMessage("密码已过期");
                }else if(exception instanceof AccountExpiredException){
                    result.setMessage("账号已过期");
                }else if(exception instanceof LockedException){
                    result.setMessage("账号被锁定");
                }else{
                    result.setMessage("未知异常");
                }

                // 把result转成JSON
                String json = objectMapper.writeValueAsString(result);

                // 返回JSON字符串
                response.setContentType("application/json;charset=UTF-8");
                PrintWriter writer = response.getWriter();
                writer.println(json);
                writer.flush();;
            }
        };
    }

    /**
     * 登出的处理器
     * @return
     */
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
                    throws IOException, ServletException {
                // 封装结果对象
                HttpResult result = HttpResult.ok().data("item", "登出成功");
                String json = objectMapper.writeValueAsString(result);
                response.setContentType("application/json;charset=UTF-8");
                PrintWriter writer = response.getWriter();
                writer.println(json);
                writer.flush();
            }
        };
    }

    /**
     * 认证成功，但是访问方法没有权限的处理器
     * @return
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request,
                               HttpServletResponse response,
                               AccessDeniedException e)
                    throws IOException, ServletException {
                // 封装结果对象
                HttpResult result = HttpResult.ok().data("item", "没有权限");
                String json = objectMapper.writeValueAsString(result);
                response.setContentType("application/json;charset=UTF-8");
                PrintWriter writer = response.getWriter();
                writer.println(json);
                writer.flush();
            }
        };
    }
}
```

## 11.8:安全配置类

```java
@Configuration
public class WebSecurityConfig {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    protected AuthenticationSuccessHandler authenticationSuccessConfig;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurerAdapter(){
        return new WebSecurityConfigurerAdapter() {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // 所有请求都需要进行认证
                http.authorizeRequests().anyRequest().authenticated();
                // 表单登录请求
                http.formLogin()
                        .successHandler(authenticationSuccessConfig) // 认证成功处理器
                        .failureHandler(authenticationFailureHandler) // 认证失败处理器
                        .permitAll(); // 允许登录请求，不需要进行认证
                // 退出成功处理器
                http.logout().logoutSuccessHandler(logoutSuccessHandler);
                // 认证成功，但是访问被拒绝的处理器
                http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```



## 11.9:JWT工具类

```java
public class JwtUtil {

    // 过期时间 15分钟
    private static final long EXPIRE_TIME = 15 * 60 * 1000;

    // 私钥
    private static final String TOKEN_SECRET = "ZZXLOVEJXL";

    /**
     * 构建Token，有效期为15分钟
     * 参数集合是参与构建Token的有效载荷部分
     * 构建成功返回字符串，构建失败返回null
     *
     * @param map
     * @return
     */
    public static String token(Map<String, Object> map) {
        try {
            // 设置过期时间
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);

            // 私钥和加密算法
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);

            // 设置头部信息
            Map<String, Object> header = new HashMap<>(2);
            header.put("typ", "jwt");
            header.put("alg", "HS256");

            // 准备构建Token字符串
            JWTCreator.Builder builder = JWT.create()
                    .withSubject("JWT") // 主题
                    .withHeader(header) // header信息
                    .withIssuedAt(new Date()) //颁发时间
                    .withExpiresAt(date); //过期时间

            // 构建Token的有效载荷部分
            map.entrySet().forEach(entry -> {
                if (entry.getValue() instanceof Integer) {
                    builder.withClaim(entry.getKey(), (Integer) entry.getValue());
                } else if (entry.getValue() instanceof Long) {
                    builder.withClaim(entry.getKey(), (Long) entry.getValue());
                } else if (entry.getValue() instanceof Boolean) {
                    builder.withClaim(entry.getKey(), (Boolean) entry.getValue());
                } else if (entry.getValue() instanceof String) {
                    builder.withClaim(entry.getKey(), String.valueOf(entry.getValue()));
                } else if (entry.getValue() instanceof Double) {
                    builder.withClaim(entry.getKey(), (Double) entry.getValue());
                } else if (entry.getValue() instanceof Date) {
                    builder.withClaim(entry.getKey(), (Date) entry.getValue());
                }
            });

            // 返回构建的Token字符串
            return builder.sign(algorithm);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证Token的正确性
     * 成功返回true，失败返回false
     *
     * @param token
     * @return
     */
    public static boolean verify(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 获取用户传入的有效载荷信息
     * 获取成功返回Map集合，获取失败返回null
     *
     * @param token
     * @return
     */
    public static Map<String, Claim> getClaims(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            Map<String, Claim> result = verifier.verify(token).getClaims();
            return result;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 获取Token过期时间
     * 获取成功返回Date对象，失败返回null
     *
     * @param token
     * @return
     */
    public static Date getExpiresAt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            return JWT.require(algorithm).build().verify(token).getExpiresAt();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 获取Token发布时间
     * 获取成功返回Date对象，失败返回null
     *
     * @param token
     * @return
     */
    public static Date getIssuedAt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            return JWT.require(algorithm).build().verify(token).getIssuedAt();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证Token是否失效
     * 失效返回true，未失效返回false
     *
     * @param token
     * @return
     */
    public static boolean isExpired(String token) {
        try {
            final Date expiration = getExpiresAt(token);
            return expiration.before(new Date());
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            return true;
        }
    }

    /**
     * 直接Base64解密获取header内容
     * 返回header的字符串表示
     *
     * @param token
     * @return
     */
    public static String getHeaderByBase64(String token) {
        if (StringUtils.isEmpty(token)) {
            return null;
        } else {
            byte[] header_byte = Base64.getDecoder().decode(token.split("\\.")[0]);
            String header = new String(header_byte);
            return header;
        }
    }

    /**
     * 直接Base64解密获取payload内容
     * 返回有效载荷的字符串表示
     *
     * @param token
     * @return
     */
    public static String getPayloadByBase64(String token) {
        if (StringUtils.isEmpty(token)) {
            return null;
        } else {
            byte[] payload_byte = Base64.getDecoder().decode(token.split("\\.")[1]);
            String payload = new String(payload_byte);
            return payload;
        }
    }
}
```

## 11.10:存入Redis

使用 Redis 把 JWT 存入 Redis

当用户登录成功，返回Token，存入 Redis，存入用户浏览器的本地存储

用户访问的时候，前端会写代码携带 Token 到 Header



用户主动点击退出的逻辑：

把 Redis 里面的这个 JWT 删除了，这样下次来的时候查询 Redis 不存在数据，这个时候则 Token 有效也无法访问

## 11.11:控制器

```java
@RestController
@RequestMapping("/student")
public class StudentController {

    @PreAuthorize(value = "hasAnyAuthority('student:query','/student/**')")
    @GetMapping("/query")
    public HttpResult query(){
        return HttpResult.ok().data("aim","query");
    }

    @PreAuthorize(value = "hasAnyAuthority('student:add','/student/**')")
    @GetMapping("/add")
    public HttpResult add(){
        return HttpResult.ok().data("aim","add");
    }

    @PreAuthorize(value = "hasAnyAuthority('student:update','/student/**')")
    @GetMapping("/update")
    public HttpResult update(){
        return HttpResult.ok().data("aim","update");
    }

    @PreAuthorize(value = "hasAnyAuthority('student:delete','/student/**')")
    @GetMapping("/delete")
    public HttpResult delete(){
        return HttpResult.ok().data("aim","delete");
    }

    @PreAuthorize(value = "hasAnyAuthority('student:export','/student/**')")
    @GetMapping("/export")
    public HttpResult export(){
        return HttpResult.ok().data("aim","export");
    }
}
```



## 11.12:小结

这个时候用户登录之后，我们就可以把用户的用户名，还有一些其他不太重要的字段封装到 JWT 里面

返回Token给用户，用户登录之后携带Token，我们使用JWT工具类解析，得到对象，就可以在前端回显了

这个时候使用 @EnableGlobalMethodSecurity(prePostEnabled = true) 启用方法级别的注解

在方法上面配置所需要的权限，分为下面两种情况：



针对角色，则使用 @PreAuthorize(value = "hasRole()") 或者 @PreAuthorize(value = "hasAnyRole()")

针对菜单，则使用 @PreAuthorize(value = "hasAuthority()") 或者 @PreAuthorize(value = "hasAnyAuthority()")

