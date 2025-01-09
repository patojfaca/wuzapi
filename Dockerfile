FROM golang:1.21-alpine AS build
RUN apk add --no-cache gcc musl-dev
RUN mkdir /app
COPY . /app
COPY .env /app/.env
WORKDIR /app
RUN go mod tidy
ENV CGO_ENABLED=1
RUN go build -o server .

FROM alpine:latest
RUN mkdir /app
COPY ./static /app/static
COPY .env /app/.env
COPY --from=build /app/server /app/
VOLUME [ "/app/dbdata", "/app/files" ]
WORKDIR /app
#ENV WUZAPI_ADMIN_TOKEN SetToRandomAndSecureTokenForAdminTasks
#ENV DB_USER=g_one
#ENV DB_PASSWORD=123mudar
#ENV DB_NAME=wuzapi
#ENV DB_HOST=localhost
#ENV DB_PORT=3306
CMD [ "/app/server", "-logtype", "json" ]