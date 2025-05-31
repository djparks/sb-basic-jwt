# Spring Boot JWT Authentication Example

This is a Spring Boot 3.2 application that demonstrates JWT authentication with Spring Security.

## Features

- User registration and login with JWT authentication
- Password encryption using BCrypt
- Role-based authorization with Spring Security
- Customized access denied handling
- Logout mechanism
- Refresh token

## Technologies

- Java 17
- Spring Boot 3.2.0
- Spring Security
- JSON Web Tokens (JWT)
- BCrypt
- Maven
- H2 Database

## Getting Started

### Prerequisites

- JDK 17
- Maven 3+

### Running the Application

1. Clone the repository
2. Navigate to the project directory
3. Run the application using Maven:

```bash
mvn spring-boot:run
```

The application will start on port 8080.

## API Endpoints

### Public Endpoints

- `POST /api/auth/signup`: Register a new user
  ```json
  {
    "username": "user",
    "email": "user@example.com",
    "password": "password",
    "roles": ["user"]
  }
  ```

- `POST /api/auth/signin`: Authenticate a user and get a JWT token
  ```json
  {
    "username": "user",
    "password": "password"
  }
  ```

- `GET /api/public/all`: Public content

### Protected Endpoints

- `GET /api/user`: User content (requires USER, MODERATOR, or ADMIN role)
- `GET /api/mod`: Moderator content (requires MODERATOR role)
- `GET /api/admin`: Admin content (requires ADMIN role)

## Authentication

To access protected endpoints, you need to include the JWT token in the Authorization header of your request:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

## User Roles

The application has three user roles:

- **USER**: Regular user with basic access
- **MODERATOR**: User with moderator privileges
- **ADMIN**: User with administrative privileges

When registering a new user, you can specify the roles. If no roles are specified, the user will be assigned the USER role by default.

## H2 Database Console

The application uses an H2 in-memory database. You can access the H2 console at:

```
http://localhost:8080/h2-console
```

Use the following credentials to log in:
- JDBC URL: `jdbc:h2:mem:testdb`
- Username: `sa`
- Password: `password`

## Security Configuration

The security configuration is defined in `WebSecurityConfig.java`. It includes:

- JWT authentication filter
- CORS configuration
- Exception handling
- Role-based authorization

## License

This project is licensed under the MIT License.