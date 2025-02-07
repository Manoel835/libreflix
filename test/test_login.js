const chai = require('chai');
const { expect } = chai;
const sinon = require('sinon');
const passport = require('passport');
const loginController = require('../controllers/user');
const chaiHttp = require('chai-http');
const app = require('../server');
const User = require('../models/User');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

chai.use(chaiHttp);

const googleProfile = {
	id: 'google123',
	displayName: 'Novo Usuário',
	emails: [{ value: 'novo.usuario@example.com' }],
};

describe('loginPost', function () {
	let req, res, next;

	beforeEach(function () {
		const validationChain = {
			isEmail: sinon.stub().returnsThis(),
			notEmpty: sinon.stub().returnsThis(),
		};

		req = {
			assert: sinon.stub().returns(validationChain),

			sanitize: sinon.stub().returns({
				normalizeEmail: sinon.stub(),
			}),

			validationErrors: sinon.stub(),
			flash: sinon.stub(),

			body: {},
			logIn: sinon.stub(),
		};

		res = {
			redirect: sinon.stub(),
		};

		next = sinon.stub();
	});

	afterEach(function () {
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

		req.logIn.callsFake((user, callback) =>
			callback(new Error('Login failed'))
		);

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

		expect(req.flash.calledWith('error', { message: 'Credenciais inválidas' }))
			.to.be.true;
		expect(res.redirect.calledWith('/login')).to.be.true;
		done();
	});

	it('CT4: Senha Ausente', function (done) {
		req.body.email = 'user@example.com';
		req.body.password = '';
		req.validationErrors.returns([{ msg: 'A senha não pode ficar em branco' }]);

		loginController.loginPost(req, res, next);

		expect(
			req.flash.calledWith('error', [
				{ msg: 'A senha não pode ficar em branco' },
			])
		).to.be.true;
		expect(res.redirect.calledWith('/login')).to.be.true;
		done();
	});

	it('CT5: E-mail Inválido', function (done) {
		req.body.email = 'invalid-email';
		req.body.password = 'password123';
		req.validationErrors.returns([{ msg: 'O e-mail inserido não é válido' }]);

		loginController.loginPost(req, res, next);

		expect(
			req.flash.calledWith('error', [{ msg: 'O e-mail inserido não é válido' }])
		).to.be.true;
		expect(res.redirect.calledWith('/login')).to.be.true;
		done();
	});

	it('CT6: E-mail Ausente', function (done) {
		req.body.email = '';
		req.body.password = 'password123';
		req.validationErrors.returns([
			{ msg: 'O e-mail não pode ficar em branco' },
		]);

		loginController.loginPost(req, res, next);

		expect(
			req.flash.calledWith('error', [
				{ msg: 'O e-mail não pode ficar em branco' },
			])
		).to.be.true;
		expect(res.redirect.calledWith('/login')).to.be.true;
		done();
	});
});

describe('Autenticação com o Google - Ciclo 1', function () {
    let sandbox, req, res, next;

    beforeEach(() => {
        sandbox = sinon.sandbox.create();
        const validationChain = {
            isEmail: sandbox.stub().returnsThis(),
            notEmpty: sandbox.stub().returnsThis(),
        };

        const sanitizeChain = {
            normalizeEmail: sandbox.stub().returnsThis(),
        };

        req = {
            body: {
                email: 'user@example.com',
                password: 'password123',
            },
            assert: sandbox.stub().returns(validationChain),
            sanitize: sandbox.stub().returns(sanitizeChain),
            validationErrors: sandbox.stub().returns(null),
            flash: sandbox.spy(),
        };

        res = {
            redirect: sandbox.spy(),
        };

        next = sandbox.stub();

        sandbox.stub(passport, 'authenticate').callsFake((strategy, callback) => {
            return function () {
                callback(null, null, { message: 'Credenciais inválidas' });
            };
        });
    });

    afterEach(() => {
        sandbox.restore();
    });

    it('Ciclo 1: Falha na Autenticação', function (done) {
        loginController.loginPost(req, res, next);

        expect(req.flash.calledWith('error', { message: 'Credenciais inválidas' })).to.be.true;
        expect(res.redirect.calledWith('/login')).to.be.true;
        done();
    });
});

describe('Autenticação com o Google - Ciclo 2', function () {
	let sandbox, findOneStub, saveStub;

	beforeEach(() => {
		sandbox = sinon.createSandbox();
		findOneStub = sandbox.stub(User, 'findOne');
		saveStub = sandbox
			.stub(User.prototype, 'save')
			.callsFake(function (callback) {
				this.googleId = googleProfile.id;
				this.name = googleProfile.displayName;
				this.email = googleProfile.emails[0].value;
				this.username = 'novoUsuario123';
				callback(null);
			});
	});

	afterEach(() => {
		sandbox.restore();
	});

	it('Ciclo 2 - Deve criar um novo usuário no banco de dados', (done) => {
		findOneStub.callsFake((query, callback) => {
			callback(null, null);
		});

		const strategy = new GoogleStrategy(
			{
				clientID: 'mock-client-id',
				clientSecret: 'mock-client-secret',
				callbackURL: '/auth/google/callback',
			},
			function (accessToken, refreshToken, profile, done) {
				User.findOne({ googleId: profile.id }, (err, user) => {
					if (!user) {
						const newUser = new User({
							googleId: profile.id,
							name: profile.displayName,
							email: profile.emails[0].value,
							username: 'novoUsuario123',
						});

						newUser.save((err) => {
							done(null, newUser);
						});
					}
				});
			}
		);

		strategy._verify(null, null, googleProfile, (err, user) => {
			expect(findOneStub.calledOnce).to.be.true;
			expect(saveStub.calledOnce).to.be.true;
			expect(user.googleId).to.equal('google123');
			expect(user.name).to.equal('Novo Usuário');
			expect(user.email).to.equal('novo.usuario@example.com');
			expect(user.username).to.equal('novoUsuario123');
			done();
		});
	});
});

describe('Autenticação com o Google - Ciclo 3', function () {
    let sandbox, findOneStub;

    beforeEach(() => {
        sandbox = sinon.sandbox.create();
        findOneStub = sandbox.stub(User, 'findOne').callsFake((query, callback) => {
            callback(null, {
                googleId: 'google123',
                name: 'Usuário Existente',
                email: 'existente@example.com',
                username: 'usuarioexistente',
            });
        });
    });

    afterEach(() => {
        sandbox.restore();
    });

    it('Ciclo 3 - Deve autenticar um usuário existente sem criar um novo registro', (done) => {
        const strategy = new GoogleStrategy(
            {
                clientID: 'mock-client-id',
                clientSecret: 'mock-client-secret',
                callbackURL: '/auth/google/callback',
            },
            function (accessToken, refreshToken, profile, done) {
                User.findOne({ googleId: profile.id }, (err, user) => {
                    if (err) return done(err);
                    if (user) {
                        return done(null, user);
                    }

                    const newUser = new User({
                        googleId: profile.id,
                        name: profile.displayName,
                        email: profile.emails[0].value,
                        username: 'novoUsuario',
                    });

                    newUser.save((err) => {
                        done(null, newUser);
                    });
                });
            }
        );

        strategy._verify(null, null, googleProfile, (err, user) => {
            expect(findOneStub.calledOnce).to.be.true;
            expect(user.googleId).to.equal('google123');
            expect(user.name).to.equal('Usuário Existente');
            expect(user.email).to.equal('existente@example.com');
            expect(user.username).to.equal('usuarioexistente');
            done();
        });
    });
});
