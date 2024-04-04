import * as React from 'react';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import CssBaseline from '@mui/material/CssBaseline';
import TextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Link from '@mui/material/Link';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import '../css/login-sign.css'
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import Cookies from "js-cookie";
import MAINURL from './ApiConfig';

function Copyright(props) {
    return (
      <Typography variant="body2" color="text.secondary" align="center" {...props}>
        {'Copyright © '}
        <Link color="inherit" href="https://carlosakel.github.io/">
          ShortUrl
        </Link>{' '}
        {new Date().getFullYear()}
        {'.'}
      </Typography>
    );
  }

// TODO remove, this demo shouldn't need to reset the theme.

const defaultTheme = createTheme();

export default function Login() {
  const navigate = useNavigate();

  async function login_user(formData) {
    const response = await axios.post(`${MAINURL}/login`, formData);
    if(response.data.token_type === "bearer"){
        Cookies.set("access_token",response.data.access_token )
        navigate("/urls");
        }
    }

  function go_to(){
        navigate("/signup");
    }
  function go_to_recover(){
    navigate("/reset-password");
  }
  const handleSubmit = (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    login_user(data);
  };

  return (
    <ThemeProvider theme={defaultTheme}>
      <Container component="main" maxWidth="xs" >
        <CssBaseline/>
        <Box
          sx={{
            marginTop: 8,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
          className="card"
          
        >
          <Avatar sx={{ m: 1, bgcolor: 'black' }}>
            <LockOutlinedIcon />
          </Avatar>
          <Typography component="h1" variant="h5">
            Sign in
          </Typography>
          <Box component="form" onSubmit={handleSubmit} noValidate sx={{ mt: 1 }} >
            <TextField
              margin="normal"
              required
              id="email"
              label="Email"
              name="email"
              autoComplete="email"
              autoFocus
              className='text-field'
            />
            <TextField
              margin="normal"
              required
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
              className='text-field'
            />
            <FormControlLabel
              control={<Checkbox value="remember" color="primary" />}
              label="Remember me"
            />
            <Button
              type="submit"
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              className='button-opts'
            >
              Sign In
            </Button>
            <Grid container >
              <Grid item xs>
                <Link href="" variant="body2" onClick={go_to_recover}>
                  Forgot password?
                </Link>
              </Grid>
              <Grid item>
                <Link href="" variant="body2"  onClick={go_to}>
                  {"Don't have an account? Sign Up"}
                </Link>
              </Grid>
            </Grid>
          </Box>
        </Box>
        <div className='card'><Copyright /></div>
      </Container>
    </ThemeProvider>
  );
}