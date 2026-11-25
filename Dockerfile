FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /work
COPY Source/ ./Source/
RUN dotnet publish Source/src/EndpointLens.Server/EndpointLens.Server.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/ ./
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
ENTRYPOINT ["dotnet", "EndpointLens.dll", "--server"]