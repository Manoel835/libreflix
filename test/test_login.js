const { expect } = require('chai');
const sinon = require('sinon');
const passport = require('passport');
const loginController = require('../controllers/user');

describe('loginPost', function () {
  let req, res, next;

  beforeEach(function () {
    const validationChain = {
      isEmail: sinon.stub().returnsThis(),
      notEmpty: sinon.stub().returnsThis()
    };

    req = {
      assert: sinon.stub().returns(validationChain),

      // Saneamento
      sanitize: sinon.stub().returns({
        normalizeEmail: sinon.stub()
      }),

      validationErrors: sinon.stub(),
      flash: sinon.stub(),

      body: {},
      logIn: sinon.stub()
    };

    res = {
      redirect: sinon.stub()
    };

    next = sinon.stub();
  });

  afterEach(function() {
    if (passport.authenticate.restore) {
      passport.authenticate.restore();
    }
  });

  it('CT1: Login Completo', function (done) {
    req.body.email = 'user@example.com';
    req.body.password = 'password123';
    req.validationErrors.returns(null);

    sinon.stub(passport, 'authenticate').callsFake((strategy, callback) => {
      return function (req, res, next) {
        callback(null, { id: 1, email: 'user@example.com' }, null);
      };
    });

    req.logIn.callsFake((user, callback) => callback(null));

    loginController.loginPost(req, res, next);

    expect(res.redirect.calledWith('/')).to.be.true;
    done();
  });

  it('CT2: Falha no Registro (mas ignora o erro)', function (done) {
    req.body.email = 'user@example.com';
    req.body.password = 'password123';
    req.validationErrors.returns(null);

    sinon.stub(passport, 'authenticate').callsFake((strategy, callback) => {
      return function (req, res, next) {
        callback(null, { id: 1, email: 'user@example.com' }, null);
      };
    });

    req.logIn.callsFake((user, callback) => callback(new Error('Login failed')));

    loginController.loginPost(req, res, next);

    expect(req.flash.calledWith('error')).to.be.false;
    expect(res.redirect.calledWith('/')).to.be.true;

    done();
  });



  it('CT3: Falha na Autenticação', function (done) {
    req.body.email = 'user@example.com';
    req.body.password = 'password123';
    req.validationErrors.returns(null);

    sinon.stub(passport, 'authenticate').callsFake((strategy, callback) => {
      return function (req, res, next) {
        callback(null, null, { message: 'Credenciais inválidas' });
      };
    });

    loginController.loginPost(req, res, next);

    expect(req.flash.calledWith('error', { message: 'Credenciais inválidas' })).to.be.true;
    expect(res.redirect.calledWith('/login')).to.be.true;
    done();
  });

  it('CT4: Senha Ausente', function (done) {
    req.body.email = 'user@example.com';
    req.body.password = '';
    req.validationErrors.returns([{ msg: 'A senha não pode ficar em branco' }]);

    loginController.loginPost(req, res, next);

    expect(req.flash.calledWith('error', [{ msg: 'A senha não pode ficar em branco' }])).to.be.true;
    expect(res.redirect.calledWith('/login')).to.be.true;
    done();
  });

  it('CT5: E-mail Inválido', function (done) {
    req.body.email = 'invalid-email';
    req.body.password = 'password123';
    req.validationErrors.returns([{ msg: 'O e-mail inserido não é válido' }]);

    loginController.loginPost(req, res, next);

    expect(req.flash.calledWith('error', [{ msg: 'O e-mail inserido não é válido' }])).to.be.true;
    expect(res.redirect.calledWith('/login')).to.be.true;
    done();
  });

  it('CT6: E-mail Ausente', function (done) {
    req.body.email = '';
    req.body.password = 'password123';
    req.validationErrors.returns([{ msg: 'O e-mail não pode ficar em branco' }]);

    loginController.loginPost(req, res, next);

    expect(req.flash.calledWith('error', [{ msg: 'O e-mail não pode ficar em branco' }])).to.be.true;
    expect(res.redirect.calledWith('/login')).to.be.true;
    done();
  });
});
