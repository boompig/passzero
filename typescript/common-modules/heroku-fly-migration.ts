export default function redirectFromHerokuToFly() {
    // hostname -> does not include port
    // host -> includes port
    if (window.location.host === 'passzero.herokuapp.com') {
        const url = new URL(window.location.href);
        url.host = 'passzero.fly.dev';
        // force the port to be the default for the protocol
        url.port = '';
        // force protocol to be HTTPS
        url.protocol = 'https:';
        console.debug(`Redirecting to ${url.toString()}...`);
        window.location.href = url.toString();
    } else {
        console.debug(`Not redirecting, hostname is ${window.location.hostname}`);
    }
}
