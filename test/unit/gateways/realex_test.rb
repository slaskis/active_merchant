require File.join(File.dirname(__FILE__) + '/../../test_helper')
require 'digest/sha1'

class RealexTest < Test::Unit::TestCase
  
  class ActiveMerchant::Billing::RealexGateway
    # For the purposes of testing, lets redefine some protected methods as public.
    public :build_purchase_or_authorization_request, :build_rebate_request, :build_void_request, :build_settle_request, :prepare_hash
  end
  
  def setup
    @login = 'your_merchant_id'
    @password = 'your_secret'
    @account = 'your_account'
    @rebate_secret = 'your_rebate_secret'
    
    @gateway = RealexGateway.new(
      :login => @login,
      :password => @password,
      :account => @account
    )

    @gateway_with_account = RealexGateway.new(
      :login => @merchant_id,
      :password => @secret,
      :account => 'bill_web_cengal'
    )
    
    @credit_card = CreditCard.new(
      :number => '4263971921001307',
      :month => 8,
      :year => 2008,
      :first_name => 'Longbob',
      :last_name => 'Longsen',
      :type => 'visa'
    )
    
    @options = {
      :order_id => '1'
    }
    
    @amount = 100
  end
  
  def test_in_test
    assert_equal :test, ActiveMerchant::Billing::Base.gateway_mode
  end  
  
  def test_hash
    result =  Digest::SHA1.hexdigest("20061213105925.yourmerchantid.1.400.EUR.4263971921001307")
    assert_equal "6bbce4d13f8e830401db4ee530eecb060bc50f64", result
    
    #add the secret to the end
    result = Digest::SHA1.hexdigest(result + "." + @password)
    assert_equal "06a8b619cbd76024676401e5a83e7e5453521af3", result
  end
  
  def test_prepare_hash
    hash_prepared = @gateway.prepare_hash('20061213105925', 'yourmerchantid', 1, 400, 'EUR', '4263971921001307')
    assert_equal "", hash_prepared
  end

  def test_successful_purchase
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
    
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_success response
    assert response.test?
  end
  
  def test_unsuccessful_purchase
    @gateway.expects(:ssl_post).returns(unsuccessful_purchase_response)
    
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_failure response
    assert response.test?
  end
  
  def test_successful_credit
    @gateway = RealexGateway.new(:login => @login, :password => @password, :rebate_secret => 'xyz')
    @gateway.expects(:ssl_post).returns(successful_credit_response)
    
    response = @gateway.credit(@amount, '1234', {:order_id => '1234', :pasref => '1234', :authcode => '1234' })
    assert_instance_of Response, response
    assert_success response
    assert response.test?
  end
  
  def test_unsuccessful_credit
    @gateway = RealexGateway.new(:login => @login, :password => @password, :rebate_secret => 'xyz')
    @gateway.expects(:ssl_post).returns(unsuccessful_credit_response)
    
    response = @gateway.credit(@amount, '1234', {:order_id => '1234', :pasref => '1234', :authcode => '1234' })
    assert_instance_of Response, response
    assert_failure response
    assert response.test?
  end
  
  def test_supported_countries
    assert_equal ['IE', 'GB'], RealexGateway.supported_countries
  end
  
  def test_supported_card_types
    assert_equal [ :visa, :master, :american_express, :diners_club, :switch, :solo, :laser ], RealexGateway.supported_cardtypes
  end
  
  def test_avs_result_not_supported
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
  
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_nil response.avs_result['code']
  end
  
  def test_cvv_result
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
  
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_equal 'M', response.cvv_result['code']
  end
  
  def test_capture_xml
    options = {
      :pasref => '1234',
      :authcode => '1234',
      :order_id => '1'
    }
    
    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')
    
    valid_capture_xml = <<-SRC
<request timestamp="20090824160201" type="settle">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>1234</pasref>
  <authcode>1234</authcode>
  <sha1hash>a28e8d7ae105d98f8cf1a014786aed77bde6485a</sha1hash>
</request>
SRC
    
    assert_equal valid_capture_xml, @gateway.build_settle_request(options)
  end
  
  def test_purchase_xml
    options = {
      :order_id => '1'
    }

    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')

    valid_purchase_request_xml = <<-SRC
<request timestamp="20090824160201" type="auth">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <amount currency="EUR">100</amount>
  <card>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <type>VISA</type>
    <chname>Longbob Longsen</chname>
    <issueno></issueno>
    <cvn>
      <number></number>
      <presind></presind>
    </cvn>
  </card>
  <autosettle flag="1"/>
  <sha1hash>3499d7bc8dbacdcfba2286bd74916d026bae630f</sha1hash>
  <tssinfo>
    <address type="billing">
      <code></code>
      <country></country>
    </address>
    <address type="shipping">
      <code></code>
      <country></country>
    </address>
    <custnum></custnum>
    <prodid></prodid>
  </tssinfo>
</request>
SRC

    assert_equal valid_purchase_request_xml, @gateway.build_purchase_or_authorization_request(:purchase, @amount, @credit_card, options)
  end
  
  def test_void_xml
    options = {
      :pasref => '1234',
      :authcode => '1234',
      :order_id => '1'
    }

    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')

    valid_void_request_xml = <<-SRC
<request timestamp="20090824160201" type="void">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>1234</pasref>
  <authcode>1234</authcode>
  <sha1hash>a28e8d7ae105d98f8cf1a014786aed77bde6485a</sha1hash>
</request>
SRC

    assert_equal valid_void_request_xml, @gateway.build_void_request(options)
  end
  
  def test_auth_xml
    options = {
      :order_id => '1'
    }

    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')

    valid_auth_request_xml = <<-SRC
<request timestamp="20090824160201" type="auth">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <amount currency=\"EUR\">100</amount>
  <card>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <type>VISA</type>
    <chname>Longbob Longsen</chname>
    <issueno></issueno>
    <cvn>
      <number></number>
      <presind></presind>
    </cvn>
  </card>
  <autosettle flag="0"/>
  <sha1hash>3499d7bc8dbacdcfba2286bd74916d026bae630f</sha1hash>
  <tssinfo>
    <address type="billing">
      <code></code>
      <country></country>
    </address>
    <address type="shipping">
      <code></code>
      <country></country>
    </address>
    <custnum></custnum>
    <prodid></prodid>
  </tssinfo>
</request>
SRC

    assert_equal valid_auth_request_xml, @gateway.build_purchase_or_authorization_request(:authorization, @amount, @credit_card, options)
  end
  
  def test_credit_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account)
    
    
    options = {
      :pasref => '1234',
      :authcode => '1234',
      :order_id => '1'
    }

    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')

    valid_credit_request_xml = <<-SRC
<request timestamp="20090824160201" type="rebate">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>1234</pasref>
  <authcode>1234</authcode>
  <amount currency="EUR">100</amount>
  <autosettle flag="1"/>
  <sha1hash>d232c3488b3822efd4f0f97bb8d6df9774cf97f7</sha1hash>
</request>
SRC

    assert_equal valid_credit_request_xml, @gateway.build_rebate_request(@amount, options)

  end
  
  def test_credit_with_rebate_secret_xml
    
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)
    
    options = {
      :pasref => '1234',
      :authcode => '1234',
      :order_id => '1'
    }

    ActiveMerchant::Billing::RealexGateway.expects(:timestamp).returns('20090824160201')

    valid_credit_request_xml = <<-SRC
<request timestamp="20090824160201" type="rebate">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>1234</pasref>
  <authcode>1234</authcode>
  <amount currency="EUR">100</amount>
  <refundhash>f94ff2a7c125a8ad87e5683114ba1e384889240e</refundhash>
  <autosettle flag="1"/>
  <sha1hash>d232c3488b3822efd4f0f97bb8d6df9774cf97f7</sha1hash>
</request>
SRC

    assert_equal valid_credit_request_xml, gateway.build_rebate_request(@amount, options)

  end
  
  private
  
  def successful_purchase_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>00</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <cardissuer>
    <bank>Issuing Bank Name</bank>
    <country>Issuing Bank Country</country>
    <countrycode>Issuing Bank Country Code</countrycode>
    <region>Issuing Bank Region</region>
  </cardissuer>
  <tss>
    <result>89</result>
    <check id="1000">9</check>
    <check id="1001">9</check>
  </tss>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end
  
  def unsuccessful_purchase_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>01</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <cardissuer>
    <bank>Issuing Bank Name</bank>
    <country>Issuing Bank Country</country>
    <countrycode>Issuing Bank Country Code</countrycode>
    <region>Issuing Bank Region</region>
  </cardissuer>
  <tss>
    <result>89</result>
    <check id="1000">9</check>
    <check id="1001">9</check>
  </tss>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end
  
  def successful_credit_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>00</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end

  def unsuccessful_credit_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>508</result>
  <message>[ test system ] You may only rebate up to 115% of the original amount.</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end
end