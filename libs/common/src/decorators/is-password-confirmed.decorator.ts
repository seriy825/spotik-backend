import { ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface } from 'class-validator';
import { SignUpDTO } from 'src/auth/dto/sign-up.dto';

@ValidatorConstraint({ name: 'IsPasswordConfirmed', async: false })
export class IsPasswordConfirmed implements ValidatorConstraintInterface {
  validate(password: string, args?: ValidationArguments): boolean | Promise<boolean> {
    const obj = args.object as SignUpDTO;
    return obj.passwordConfirmation === password;
  }
  defaultMessage(validationArguments?: ValidationArguments): string {
    return 'Passwords is not match!';
  }
}
