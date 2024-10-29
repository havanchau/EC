import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth, AuthDocument } from './auth.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Auth.name) private authModel: Model<AuthDocument>,
    private jwtService: JwtService,
  ) {}

  async register(username: string, password: string): Promise<Auth> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.authModel({ username, password: hashedPassword });
    return newUser.save();
  }

  async login(username: string, password: string): Promise<{ accessToken: string } | null> {
    const user = await this.authModel.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
      const accessToken = this.jwtService.sign({ username: user.username, sub: user._id });
      return { accessToken };
    }
    return null;
  }
}
