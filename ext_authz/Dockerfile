# Light base image
FROM node:20-alpine

# Set up working dir
WORKDIR /app

# Copy important file from module ext_authz
COPY package*.json ./

# Install project's package
RUN npm install --omit=dev

# Copy all code from module to container
COPY . .

# Port to run service
EXPOSE 50051

# Command to run service
CMD ["node", "index.js"]