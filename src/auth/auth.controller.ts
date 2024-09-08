import { Body, Controller, Get, Post, Query, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBody, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOkResponse({ status: 200 })
  @ApiBody({
    type: LoginDto,
    description: 'Login Dto',
  })
  async login(@Body() body: LoginDto, @Req() req: Request) {
    return this.authService.login(body, req.ip);
  }

  @Get('validate/link')
  @ApiOkResponse({ status: 200 })
  async validateLink(
    @Query() query: { token: string },
  ): Promise<{ message: string }> {
    return this.authService.validateMagicLink(query.token);
  }
}
