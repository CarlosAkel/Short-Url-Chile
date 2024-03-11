
import '../css/inputUrl.css'
import '../css/button.css'
function UrlShort() {
  return (
    <div>
      <div class="url">
        <p>Shorten Your Url </p>
        <input placeholder="Your Url" class="url-input" name="email" type="email" />
        <br />
        <div class="submit-btn">SUBMIT</div>
      </div>

      <div class="card">

        <div>Here you can login and obtain the list of your Urls</div>
        <div></div>
        <button>
          <span class="circle1"></span>
          <span class="circle2"></span>
          <span class="circle3"></span>
          <span class="circle4"></span>
          <span class="circle5"></span>
          <span class="text">Login</span>
        </button>
      </div>
    </div>
  );
}

export default UrlShort;
