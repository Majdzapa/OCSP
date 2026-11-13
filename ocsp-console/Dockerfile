# Multi-stage: build React SPA → serve with Nginx
FROM node:20-alpine AS build
WORKDIR /app

# Accept build-time env vars (baked into the bundle)
ARG VITE_API_BASE_URL=""
ARG VITE_AUTH_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_AUTH_BASE_URL=$VITE_AUTH_BASE_URL

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

COPY . .
RUN yarn build

# Production stage: lightweight Nginx Alpine
FROM nginx:1.27-alpine
LABEL org.opencontainers.image.title="OCSP Admin Console"
LABEL org.opencontainers.image.description="React 18 admin dashboard for the OCSP subsystem"

# Copy built SPA assets
COPY --from=build /app/dist /usr/share/nginx/html

# Nginx config: SPA fallback + reverse proxy for /api and /oauth2
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
