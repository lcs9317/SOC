# Node.js LTS 버전 기반 이미지 사용 (여기서는 Alpine 버전 사용)
FROM node:18-alpine

# 작업 디렉토리 생성
WORKDIR /usr/src/app

# package.json 및 package-lock.json 복사
COPY package*.json ./

# 애플리케이션 의존성 설치
RUN npm install

# 애플리케이션 소스 복사
COPY . .

# 컨테이너가 리슨할 포트 노출 (여기서는 3000 사용)
EXPOSE 3000

# 서버 실행
CMD ["node", "server.js"]
