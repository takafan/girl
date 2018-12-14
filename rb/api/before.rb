before do
  response.headers[ "Access-Control-Allow-Origin" ] = "*"

  if request.request_method == 'OPTIONS'
    response.headers[ "Access-Control-Allow-Methods" ] = 'POST'
    response.headers[ "Access-Control-Allow-Headers" ] = 'Content-Type'

    halt 200
  end

  content_type :json, charset: 'utf-8'
end
