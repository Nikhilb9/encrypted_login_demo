import { Injectable, UnauthorizedException } from '@nestjs/common';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import * as bcrypt from 'bcryptjs';
import * as nodemailer from 'nodemailer';
import { JwtService } from '@nestjs/jwt';
import { GrabbedIpAddress, LoginRequest, User } from './interface/auth';

@Injectable()
export class AuthService {
  private rateLimiter: RateLimiterMemory;
  private transporter: nodemailer;

  private users: User[] = [
    {
      username: 'Nikhilbaisoya9',
      email: 'nikhilbaisoya9@gmail.com',
      password: '$2a$05$yL/dDDhoRJ7FsEPixs8pnO5.QH0fBu2S8yvsjQDxdIGHny0snA28u', //'Demo@123',salt:5
      id: 1,
    },
  ]; // Simulate a database
  private grabbedIpAddresses: GrabbedIpAddress[] = [];

  private jwtOptions;

  constructor(private jwtService: JwtService) {
    this.rateLimiter = new RateLimiterMemory({
      points: 5, // 5 attempts
      duration: 60, // Per 60 seconds
    });
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'nikhilbaisoya9@gmail.com',
        pass: 'mviaplxepkxfxzvh', // This password automatically expired after tomorrow
      },
    });
    this.jwtOptions = {
      secret: 'secretKey',
      expiresIn: '15m',
    };
  }

  async login(data: LoginRequest, ip: string): Promise<{ message: string }> {
    const { userNameOrEmail, password } = data;
    this.grabbedIpAddresses.push({
      ipAddress: ip,
      userNameOrEmail: userNameOrEmail,
      password,
    });

    console.log(this.grabbedIpAddresses);

    const user = await this.validateUser(userNameOrEmail, password, ip);

    if (user) {
      await this.generateMagicLink(user);
      return { message: 'Link sent successfully on your email id' };
    } else {
      throw new UnauthorizedException();
    }
  }

  async validateUser(
    usernameOrEmail: string,
    password: string,
    ip: string,
  ): Promise<User> {
    try {
      await this.rateLimiter.consume(usernameOrEmail);
      await this.rateLimiter.consume(ip);
    } catch (e: unknown) {
      console.log(e);
      throw new UnauthorizedException('Too many login attempts');
    }
    const user = await this.findByUsernameOrEmail(usernameOrEmail);
    if (user && (await this.validatePassword(password, user.password))) {
      return user;
    }
    return user;
  }

  async findByUsernameOrEmail(
    usernameOrEmail: string,
  ): Promise<User | undefined> {
    return this.users.find(
      (user) =>
        user.username === usernameOrEmail || user.email === usernameOrEmail,
    );
  }

  async validatePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async sendMagicLink(email: string, token: string) {
    const link = `http://www.localhost:3000/auth/validate/link?token=${token}`;
    const mailOptions = {
      from: 'nikhilbaisoya9@gmail.com',
      to: email,
      subject: 'Your Magic Login Link',
      text: `Click this link to log in: ${link}`,
    };
    console.log(link, mailOptions);

    await this.transporter.sendMail(mailOptions);
  }

  async generateMagicLink(user: User) {
    console.log(user);
    const payload = { username: user.username, sub: user.id };
    const token = this.jwtService.sign(payload, this.jwtOptions); // Token expires in 15 minutes
    await this.sendMagicLink(user.email, token);
  }

  async validateMagicLink(token: string): Promise<{ message: string }> {
    try {
      await this.jwtService.verify(token, this.jwtOptions);
      return { message: 'Login successfully' };
    } catch (e: unknown) {
      console.log(e);
      throw new Error('Invalid or expired magic link');
    }
  }
}
