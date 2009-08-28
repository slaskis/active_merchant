require 'rexml/document'
require 'digest/sha1'

module ActiveMerchant
  module Billing
    # Realex us the leading CC gateway in Ireland
    # see http://www.realexpayments.com
    # Contributed by John Ward (john@ward.name)
    # see http://thinedgeofthewedge.blogspot.com
    # 
    # Realex works using the following
    # login - The unique id of the merchant
    # password - The secret is used to digitally sign the request
    # account - This is an optional third part of the authentication process
    # and is used if the merchant wishes do distuinguish cc traffic from the different sources
    # by using a different account. This must be created in advance
    #
    # the Realex team decided to make the orderid unique per request, 
    # so if validation fails you can not correct and resend using the 
    # same order id
    class RealexGateway < Gateway
      URL = 'https://epage.payandshop.com/epage-remote.cgi'
                  
      CARD_MAPPING = {
        'master'            => 'MC',
        'visa'              => 'VISA',
        'american_express'  => 'AMEX',
        'diners_club'       => 'DINERS',
        'switch'            => 'SWITCH',
        'solo'              => 'SWITCH',
        'laser'             => 'LASER'
      }
      
      self.money_format = :cents
      self.default_currency = 'EUR'
      self.supported_cardtypes = [ :visa, :master, :american_express, :diners_club, :switch, :solo, :laser ]
      self.supported_countries = [ 'IE', 'GB' ]
      self.homepage_url = 'http://www.realexpayments.com/'
      self.display_name = 'Realex'
           
      SUCCESS, DECLINED          = "Successful", "Declined"
      BANK_ERROR = REALEX_ERROR  = "Gateway is in maintenance. Please try again later."
      ERROR = CLIENT_DEACTIVATED = "Gateway Error"
      
      def initialize(options = {})
        requires!(options, :login, :password)
        options[:refund_hash] = Digest::SHA1.hexdigest(options[:rebate_secret]) if options.has_key?(:rebate_secret)
        @options = options
        super
      end  

      # Performs an authorization, which reserves the funds on the customer's credit card, but does not
      # charge the card.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be authorized. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- The application generated order identifier. (REQUIRED)
      def authorize(money, creditcard, options = {})
        requires!(options, :order_id)
        
        request = build_purchase_or_authorization_request(:authorization, money, creditcard, options) 
        commit(request)
      end
      
      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be purchased. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- The application generated order identifier. (REQUIRED)
      def purchase(money, creditcard, options = {})
        requires!(options, :order_id)
        
        request = build_purchase_or_authorization_request(:purchase, money, creditcard, options)
        commit(request)
      end
      
      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- The application generated order identifier. (REQUIRED)
      # * <tt>:pasref</tt> -- The realex payments reference of the original transaction. (REQUIRED)
      # * <tt>:authcode</tt> -- The authcode of the original transaction. (REQUIRED)
      def capture(money, authorization, options = {})
        options.merge!(:authcode => authorization)
        requires!(options, :authcode)
        requires!(options, :pasref)
        requires!(options, :order_id)
        
        request = build_capture_request(options) 
        commit(request)
      end
      
      # Credit an account.
      #
      # This transaction is also referred to as a Refund (or Rebate) and indicates to the gateway that
      # money should flow from the merchant to the customer.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be credited to the customer. Either an Integer value in cents or a Money object.
      # * <tt>identification</tt> -- The ID of the original transaction against which the credit is being issued.
      # * <tt>options</tt> -- A hash of parameters.
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- The application generated order identifier. (REQUIRED)
      # * <tt>:pasref</tt> -- The realex payments reference of the original transaction. (REQUIRED)
      # * <tt>:authcode</tt> -- The authcode of the original transaction. (REQUIRED)
      def credit(money, identification, options = {})
        options.merge!(:order_id => identification)
        requires!(options, :pasref)
        requires!(options, :authcode)
        
        request = build_credit_request(money, options)
        commit(request)
      end
      
      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      #
      # ==== Options
      #
      # * <tt>:order_id</tt> -- The application generated order identifier. (REQUIRED)
      # * <tt>:pasref</tt> -- The realex payments reference of the original transaction. (REQUIRED)
      # * <tt>:authcode</tt> -- The authcode of the original transaction. (REQUIRED)
      def void(identification, options = {})
        options.merge!(:order_id => identification)
        requires!(options, :order_id)
        requires!(options, :pasref)
        requires!(options, :authcode)
        
        request = build_void_request(options) 
        commit(request)
      end

      private
      def commit(request)
        response = ssl_post(URL, request)
        parsed = parse(response)
        
        Response.new(parsed[:result] == "00", message_from(parsed), parsed,
          :test => parsed[:message] =~ /\[ test system \]/,
          :authorization => parsed[:authcode],
          :cvv_result => parsed[:cvnresult],
          :raw_response => response
        )      
      end

      def parse(xml)
        response = {}
        
        xml = REXML::Document.new(xml)          
        xml.elements.each('//response/*') do |node|

          if (node.elements.size == 0)
            response[node.name.downcase.to_sym] = normalize(node.text)
          else
            node.elements.each do |childnode|
              name = "#{node.name.downcase}_#{childnode.name.downcase}"
              response[name.to_sym] = normalize(childnode.text)
            end              
          end

        end unless xml.root.nil?
        
        response
      end
      
      def build_purchase_or_authorization_request(action, money, credit_card, options)
        timestamp = self.class.timestamp
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'auth' do
          add_merchant_details(xml, options)
          xml.tag! 'orderid', sanitize_order_id(options[:order_id])
          add_ammount(xml, money, options)
          add_card(xml, credit_card)
          xml.tag! 'autosettle', 'flag' => auto_settle_flag(action)
          add_signed_digest(xml, timestamp, @options[:login], options[:order_id], amount(money), (options[:currency] || currency(money)), credit_card.number)
          add_comments(xml, options)
          add_address_and_customer_info(xml, options)
        end
        xml.target!
      end
      
      def build_capture_request(options)
        timestamp = self.class.timestamp
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'settle' do
          add_merchant_details(xml, options)
          add_transaction_identifiers(xml, options)
          add_comments(xml, options)
          add_signed_digest(xml, timestamp, @options[:login], options[:order_id])
        end
        xml.target!
      end
      
      def build_credit_request(money, options)
        timestamp = self.class.timestamp
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'rebate' do
          add_merchant_details(xml, options)
          add_transaction_identifiers(xml, options)
          xml.tag! 'amount', amount(money), 'currency' => options[:currency] || currency(money)
          xml.tag! 'refundhash', @options[:refund_hash] if @options[:refund_hash]
          xml.tag! 'autosettle', 'flag' => 1          
          add_comments(xml, options)
          add_signed_digest(xml, timestamp, @options[:login], options[:order_id], amount(money), (options[:currency] || currency(money)))
        end
        xml.target!
      end
      
      def build_void_request(options)
        timestamp = self.class.timestamp
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'void' do
          add_merchant_details(xml, options)
          add_transaction_identifiers(xml, options)
          add_comments(xml, options)
          add_signed_digest(xml, timestamp, @options[:login], options[:order_id])
        end
        xml.target!
      end
      
      def add_address_and_customer_info(xml, options)
        billing_address = options[:billing_address] || options[:address]
        shipping_address = options[:shipping_address]
        
        return unless billing_address || shipping_address || options[:customer] || options[:invoice] || options[:ip]
        
        xml.tag! 'tssinfo' do
          
          xml.tag! 'custnum', options[:customer] if options[:customer]
          xml.tag! 'prodid', options[:invoice] if options[:invoice]
          xml.tag! 'custipaddress', options[:ip] if options[:ip]
          # xml.tag! 'varref' 
          
          if billing_address
            xml.tag! 'address', 'type' => 'billing' do
              xml.tag! 'code', billing_address[:zip]
              xml.tag! 'country', billing_address[:country]
            end
          end
          
          if shipping_address
            xml.tag! 'address', 'type' => 'shipping' do
              xml.tag! 'code', shipping_address[:zip]
              xml.tag! 'country', shipping_address[:country]
            end
          end
          
        end
      end
      
      def add_merchant_details(xml, options)
        xml.tag! 'merchantid', @options[:login] 
        if options[:account] || @options[:account]
          xml.tag! 'account', options[:account] || @options[:account]
        end
      end
      
      def add_transaction_identifiers(xml, options)
        xml.tag! 'orderid', sanitize_order_id(options[:order_id])
        xml.tag! 'pasref', options[:pasref]
        xml.tag! 'authcode', options[:authcode]
      end
      
      def add_comments(xml, options)
        return unless options[:description]
        xml.tag! 'comments' do
          xml.tag! 'comment', options[:description], 'id' => 1 
        end
      end
      
      def add_ammount(xml, money, options)
        xml.tag! 'amount', amount(money), 'currency' => options[:currency] || currency(money)
      end
      
      def add_card(xml, credit_card)
        xml.tag! 'card' do
          xml.tag! 'number', credit_card.number
          xml.tag! 'expdate', expiry_date(credit_card)
          xml.tag! 'chname', credit_card.name
          xml.tag! 'type', CARD_MAPPING[card_brand(credit_card).to_s]
          xml.tag! 'issueno', credit_card.issue_number
          xml.tag! 'cvn' do
            xml.tag! 'number', credit_card.verification_value
            xml.tag! 'presind', (options['presind'] || (credit_card.verification_value? ? 1 : nil))
          end
        end
      end
      
      def stringify_values(values)
        string = ""
        (0..5).each do |i|
          string << "#{values[i]}"
          string << "." unless i == 5
        end
        string
      end
      
      def add_signed_digest(xml, *values)
        string = stringify_values(values)
        xml.tag! 'sha1hash', sha1from(string)
      end
      
      def auto_settle_flag(action)
        action == :authorization ? '0' : '1'
      end
      
      def expiry_date(credit_card)
        "#{format(credit_card.month, :two_digits)}#{format(credit_card.year, :two_digits)}"
      end
      
      def sha1from(string)
        Digest::SHA1.hexdigest("#{Digest::SHA1.hexdigest(string)}.#{@options[:password]}")
      end
      
      def normalize(field)
        case field
        when "true"   then true
        when "false"  then false
        when ""       then nil
        when "null"   then nil
        else field
        end        
      end
      
      def message_from(response)
        message = nil
        case response[:result]                
        when "00"
          message = SUCCESS
        when "101"
          message = response[:message]
        when "102", "103"
          message = DECLINED
        when /^2[0-9][0-9]/
          message = BANK_ERROR
        when /^3[0-9][0-9]/
          message = REALEX_ERROR
        when /^5[0-9][0-9]/
          message = ERROR
        when "666"
          message = CLIENT_DEACTIVATED
        else
          message = DECLINED
        end  
      end
      
      def sanitize_order_id(order_id)
        order_id.to_s.gsub(/[^a-zA-Z0-9\-_]/, '')
      end
      
      def self.timestamp
        Time.now.strftime('%Y%m%d%H%M%S')
      end
    end
  end
end