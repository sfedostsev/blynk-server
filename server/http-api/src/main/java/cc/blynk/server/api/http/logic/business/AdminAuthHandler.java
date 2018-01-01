package cc.blynk.server.api.http.logic.business;

import cc.blynk.core.http.BaseHttpHandler;
import cc.blynk.core.http.Response;
import cc.blynk.core.http.annotation.Consumes;
import cc.blynk.core.http.annotation.FormParam;
import cc.blynk.core.http.annotation.POST;
import cc.blynk.core.http.annotation.Path;
import cc.blynk.server.Holder;
import cc.blynk.server.core.dao.SessionDao;
import cc.blynk.server.core.dao.UserDao;
import cc.blynk.server.core.model.auth.User;
import cc.blynk.utils.AppNameUtil;
import cc.blynk.utils.http.MediaType;
import io.netty.channel.ChannelHandler;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static cc.blynk.core.http.Response.redirect;
import static io.netty.handler.codec.http.HttpHeaderNames.SET_COOKIE;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 09.12.15.
 */
@Path("")
@ChannelHandler.Sharable
public class AdminAuthHandler extends BaseHttpHandler {

    private static final Logger log = LogManager.getLogger(AdminAuthHandler.class);

    //1 month
    private static final int COOKIE_EXPIRE_TIME = 30 * 60 * 60 * 24;

    private final UserDao userDao;

    public AdminAuthHandler(Holder holder, String adminRootPath) {
        super(holder, adminRootPath);
        this.userDao = holder.userDao;
    }

    @POST
    @Consumes(value = MediaType.APPLICATION_FORM_URLENCODED)
    @Path("/login")
    public Response login(@FormParam("email") String email,
                          @FormParam("password") String password) {

        if (email == null || password == null) {
            log.debug("Empty email and/or password");
            return redirect(rootPath);
        }

        User user = userDao.getByName(email, AppNameUtil.BLYNK);

        if (user == null || !user.isSuperAdmin) {
            log.debug("User '{}' is not defined or it's not an admin.", email);
            return redirect(rootPath);
        }

        if (!password.equals(user.pass)) {
            log.debug("Incorrect password provided for user '{}'", user.email);
            return redirect(rootPath);
        }

        Response response = redirect(rootPath);

        log.debug("Admin login is successful. Redirecting to {}", rootPath);

        Cookie cookie = makeDefaultSessionCookie(sessionDao.generateNewSession(user), COOKIE_EXPIRE_TIME);
        response.headers().add(SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));

        return response;
    }

    @POST
    @Path("/logout")
    public Response logout() {
        Response response = redirect(rootPath);
        Cookie cookie = makeDefaultSessionCookie("", 0);
        response.headers().add(SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));
        return response;
    }

    private static Cookie makeDefaultSessionCookie(String sessionId, int maxAge) {
        DefaultCookie cookie = new DefaultCookie(SessionDao.SESSION_COOKIE, sessionId);
        cookie.setMaxAge(maxAge);
        return cookie;
    }

}
