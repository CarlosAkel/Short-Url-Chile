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

export default function SignUp() {
    const navigate = useNavigate()

    async function create_user(formData) {
        const response = await axios.post(`${MAINURL}/user`, formData);
        if (response.data.Response === "OK") {
            navigate("/login");
        }
    }

    function go_to(){
        navigate("/login");
    }

    const handleSubmit = async (event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        create_user(data);
    };

    return (
        <ThemeProvider theme={defaultTheme}>
            <Container component="main" maxWidth="xs">
                <CssBaseline />
                <Box
                    sx={{
                        marginTop: 28,
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
                        Sign up
                    </Typography>
                    <Box component="form" noValidate onSubmit={handleSubmit} sx={{ mt: 3 }}>
                        <Grid>
                            <Grid item xs={12} sm={6}>
                                <TextField
                                    autoComplete="given-name"
                                    name="username"
                                    required
                                    id="username"
                                    label="Username"
                                    autoFocus
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <TextField
                                    required
                                    id="email"
                                    label="Email Address"
                                    name="email"
                                    autoComplete="email"
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <TextField
                                    required
                                    name="password"
                                    label="Password"
                                    type="password"
                                    id="password"
                                    autoComplete="new-password"
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <FormControlLabel
                                    control={<Checkbox value="allowExtraEmails" color="primary" />}
                                    label="I want to receive inspiration, marketing promotions and updates via email."
                                />
                            </Grid>
                        </Grid>

                        <div className='center-button '>
                            <Button
                                type="submit"
                                variant="contained"
                                sx={{ mt: 3, mb: 2 }}
                                className='button-opts'
                            >
                                Sign Up
                            </Button>
                        </div>


                    </Box>
                    <Grid container className='center-button'>
                        <Grid item>
                            <div onClick={go_to}>
                                <Link href="" variant="body2">
                                    Already have an account? Sign in
                                </Link>
                            </div>
                        </Grid>
                    </Grid>
                </Box>
                <div className='card'><Copyright /></div>
            </Container>
        </ThemeProvider>
    );
}