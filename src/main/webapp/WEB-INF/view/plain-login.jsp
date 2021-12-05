<%--
  Created by IntelliJ IDEA.
  User: vyom
  Date: 27/11/21
  Time: 5:17 PM
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
<h3>My Custom Login Page</h3>

<!-- form:form is the best practice
as it provides automatic support for security defenses,
 it automagicaly adds CSRF token-->

<<%--form:--%>form action="${pageContext.request.contextPath}/authenticateTheUser"
           method="post">

    <!-- Check if user logged out -->
    <c:if test="${param.logout != null}">
        <i style="color: green">You Successfully logged out</i>
    </c:if>

    <!-- Check for login error -->
    <c:if test="${param.error != null}">
        <i style="color: red">Sorry you entered wrong credentials....</i>
    </c:if>

    <p>
        <!-- 'username' and 'password' are default field names that spring
        looks up for -->
        User Name: <label>
        <input type="text" name="username">
    </label>
    </p>
    <p>
        Password: <label>
        <input type="password" name="password">
    </label>
    </p>
    <input type="submit" value="Login">

    <!-- I am manually adding tokens -->
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">

</<%--form:--%>form>


</body>
</html>
