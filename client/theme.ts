import { createTheme, ThemeOptions } from '@material-ui/core/styles';

const theme = createTheme({
  typography: {
    allVariants: {
      color: '#FFF',
    },
  },
  palette: {
    primary: {
      light: '#5c67a3',
      main: '#3f4771',
      dark: '#2e355b',
      contrastText: '#fff',
    },
    secondary: {
      light: '#ff79b0',
      main: '#ff4081',
      dark: '#c60055',
      contrastText: '#000',
    },
    openTitle: teal['700'],
    protectedTitle: '#f57c00',
    type: 'light',
  },
});

export default theme;
