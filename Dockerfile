FROM node:8

WORKDIR /app/
COPY ./package*.json /app/
RUN npm install

COPY ./ /app/

ENV PORT=3000
ENV DB_HOST=34.86.218.160
ENV DB_PORT=3306
ENV DB_USERNAME=root
ENV DB_PASSWORD=toor
ENV DB_NAME=assignment2

EXPOSE 3000
CMD ["npm", "start"]