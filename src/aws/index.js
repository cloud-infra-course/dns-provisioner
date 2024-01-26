function parseJwt (token) {
  const base64Url = token.split('.')[1]
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
  const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
  }).join(''))
  
  return JSON.parse(jsonPayload)
}

function onSignIn (googleUser) {
  const payload = parseJwt(googleUser.credential)
  localStorage.setItem('credential', googleUser.credential + `; ${payload.exp}`)
}

function provisionNameServers () {
  const credential = localStorage.getItem('credential')
  if (credential === null || Number(credential.split('; ')[1]) < new Date().getTime() / 1000) {
    localStorage.removeItem('credential')
    openPopup('Error', 'Missing or expired session. Try signing in again.')
    return
  }
  
  // Make a POST request to the API endpoint
  fetch('/aws/credits', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${credential.split('; ')[0]}`,
    },
  })
  .then(async function (response) {
    if (response.ok) {
      // API request was successful
      return await response.json()
    } else {
      let errorText = ''
      // API request failed
      if (response.status === 400) {
        errorText = "Something went wrong."
      } else if (response.status === 403) {
        errorText = "Unauthorized. Please check that you're signing in with a Stanford Google account."
      } else if (response.status === 500) {
        errorText = "Internal server error. Try again later or contact the instructors if this continues."
      } else if (response.status === 501) {
        errorText = "This functionality is disabled until further notice."
      }
      throw new Error(errorText)
    }
  })
  .then(function (responsePayload) {
    // Handle the successful response from the API
    openPopup('Success', responsePayload.code)
    // You can render a success message or take further actions here
  })
  .catch(function (error) {
    // Handle errors
    openPopup('Error', `An error occurred while processing your request: ${error}`)
    // Render an error message or take appropriate actions
  })
}

// JavaScript function to open the popup with success or error message
function openPopup (title, content) {
  const popup = document.getElementById('popup')
  const popupTitle = document.getElementById('popupTitle')
  const popupContent = document.getElementById('popupContent')
  
  popupTitle.textContent = title
  popupContent.textContent = content
  
  popup.classList.remove('hidden')
}

// JavaScript function to close the popup
function closePopup () {
  const popup = document.getElementById('popup')
  popup.classList.add('hidden')
}

const provisionButton = document.getElementById('submit')
if (provisionButton) {
  provisionButton.addEventListener('click', provisionNameServers)
}

// Attach event listener to the close button
const popupCloseButton = document.getElementById('popupClose')
if (popupCloseButton) {
  popupCloseButton.addEventListener('click', closePopup)
}
