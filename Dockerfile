# Stage 1: Build the application
FROM dart:stable AS build

# Set working directory and copy dependencies
WORKDIR /app
COPY pubspec.* ./
RUN dart pub get

# Copy source code and compile the Dart app to a native executable
COPY . .
RUN dart compile exe bin/server.dart -o bin/server

# Stage 2: Build minimal serving image
FROM dart:stable AS runtime

# Copy the AOT-compiled executable and required runtime
WORKDIR /app
COPY --from=build /app/bin/server /app/bin/

# Expose the port your server will run on
EXPOSE 8080
EXPOSE 27017

# Run the AOT-compiled executable directly (no need for `dart` command)
CMD ["/app/bin/server"]

