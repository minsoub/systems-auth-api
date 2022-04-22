## **프로젝트 소개**
- 인증 서버

## **기술 스택 소개**

- Java version : JDK 13
- Spring Boot : 2.6.6
- Build : Gradle 7.1
- Spring Data MongoDB Reactive
- Spring Data Redis Reactive
- Spring Boot Actuator
- Spring Docs Openapi

## **프로젝트 구조**

- API 모듈 구성
  - auth-api
  - auth-data
      - mongodb
      - redis

### TODO
- Build script
- exception
- Audit
- code coverage
- Prometheus/Grafana 연동

## Running the tests
- Swagger 참고
    - http://127.0.0.1:8080/swagger-ui.html
- Docker(mongodb)
    - docker-compose.yml
      mongo

> **docker exec -it dev-mongo bash**

> mongo

> use admin

> db.auth(’systems’,’1234’)

> use test

> db.createUser(
{	user: "bit",
pwd: "thumb",
roles:[{role: "readWrite" , db:"test"}]
})

## history
- 0.0.1 초안 init

### License 
