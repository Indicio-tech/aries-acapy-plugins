import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import "./InputForm.css"

const InputForm = () => {
  const navigate = useNavigate();
  const [firstName, setFirstName] = useState('Bob');
  const [lastName, setLastName] = useState('Builder');
  const [email, setEmail] = useState('bobsthearchitect@email.com');
  const [did, setDid] = useState('');
  const [credential, setCredential] = useState('');

  const handleFirstNameChange = (e) => {
    setFirstName(e.target.value);
  };

  const handleLastNameChange = (e) => {
    setLastName(e.target.value);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const handleCredentialChange = (e) => {
    setCredential(e.target.value);
  };

  const handleDidChange = (e) => {
    setDid(e.target.value);
  };

  const handleShareClick = () => {
    navigate(`/credentials`,{ state: {firstName:firstName, lastName:lastName, email:email, did:did, credential:credential}});
    
  };

  return (
   <div class="container" style={{padding: "3px"}}>
     <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6 input-wrapper">
        <h1 class="input-h1">OID4VCI Demo</h1>
        <hr />
        <div>
          <form class="input-form">
              <div class="input-form-group">
                <label htmlFor="firstName" class="input-label">First Name</label>
                <br />
                <input
                  type="text"
                  id="firstName"
                  value={firstName}
                  onChange={handleFirstNameChange}
                  class="input-form-control"
                />
              </div>

              <div class="input-form-group">
                <label htmlFor="lastName" class="input-label">Last Name</label>
                <br />
                <input
                  type="text"
                  id="lastName"
                  value={lastName}
                  onChange={handleLastNameChange}
                  class="input-form-control"
                />
              </div>

              <div class="input-form-group">
                <label htmlFor="email" class="input-label">Email</label>
                <br />
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={handleEmailChange}
                  class="input-form-control"
                />
              </div>

              <div class="input-form-group">
                <label htmlFor="did" class="input-label">DID</label>
                <br />
                <input
                  type="did"
                  id="did"
                  value={did}
                  onChange={handleDidChange}
                  class="input-form-control"
                />
              </div>

              <div class="input-form-group">
                <label htmlFor="credential" class="input-label">Credential</label>
                <br />
                <input
                  type="credential"
                  id="credential"
                  value={credential}
                  onChange={handleCredentialChange}
                  class="input-form-control"
                />
              </div>

              <div class="input-form-group">
                <button type="button" onClick={handleShareClick} class="btn btn-warning btn-lg input-form-button" data-toggle="button" aria-pressed="false" autocomplete="off">Share</button>
              </div>
            </form>
          </div>
        </div>
      <div class="col-md-3"></div>
      </div>
    </div>
  );
};

export default InputForm; 
