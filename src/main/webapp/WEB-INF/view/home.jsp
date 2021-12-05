<%--
  Created by IntelliJ IDEA.
  User: vyom
  Date: 26/11/21
  Time: 6:45 PM
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>

<html>
<head>
    <title>Welcome to Home..</title>
</head>
<body>
<h2>Spring is boring, I am dead serious for creating babatunde</h2>


<hr>

<!-- display ser name and roles -->
<p>
User: <security:authentication property="principal.username" />
    <br><br>
Role(s): <security:authentication property="principal.authorities" />
</p>

<hr>
<!-- add a link to point to owner, only owner can see this link -->
<security:authorize access="hasRole('OWNER')">
<p>
    <a href="${pageContext.request.contextPath}/owner">Owner</a>
</p>
</security:authorize>
<security:authorize access="hasRole('TESTER')">
<p>
    <a href="${pageContext.request.contextPath}/tester">Tester</a>
</p>
</security:authorize>

<p>
    <form:form action="${pageContext.request.contextPath}/logout" method="post">
        <input type="submit" value="logout">
    </form:form>
</p>
</body>
</html>
