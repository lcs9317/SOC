const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();

// POST 요청의 body를 파싱
app.use(bodyParser.urlencoded({ extended: false }));

// EJS 템플릿 엔진 사용 설정
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 데모용 인메모리 사용자 저장소 (실제 서비스에서는 DB 연동 필요)
const users = {};

// GET: 로그인 페이지 ("/"와 "/login" 모두 처리)
app.get(['/', '/login'], (req, res) => {
  res.render('login', { error: null });
});

// POST: 로그인 처리
app.post('/login', (req, res) => {
    const { id, pw } = req.body;
    if (users[id] && users[id].password === pw) {
      // 로그인 성공 시 Kibana 대시보드로 리디렉션
      // 상대 URL 사용: 클라이언트가 현재 사용 중인 호스트와 포트를 그대로 사용함.
      res.redirect('/kibana');
    } else {
      res.render('login', { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }
  });
  

// GET: 회원가입 페이지
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// POST: 회원가입 처리
app.post('/register', (req, res) => {
  const { id, pw } = req.body;
  if (users[id]) {
    res.render('register', { error: '이미 존재하는 아이디입니다.' });
  } else {
    users[id] = { password: pw };
    res.redirect('/');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth service is running on port ${PORT}`);
});
